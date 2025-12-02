"""
Cross-function memory flow analyzer that integrates CFG building, alias table construction,
and path analysis across multiple functions.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

import analysis_operators
from function_ast_cfg import FunctionCFGAnalyzer
from analyzers.path_builder_agent import FunctionPathBuilderAgent
from utils import find_code_line, extract_lhs_variable

logger = logging.getLogger(__name__)


class GlobalAliasTable:
    """Maintains a global alias table across multiple functions."""
    
    def __init__(self):
        # Variable name -> set of all aliases
        self._aliases: Dict[str, Set[str]] = defaultdict(set)
        # Variable name -> list of alias sources (function, location, aliases)
        self._alias_sources: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Track alias relationships: (var1, var2) means var1 and var2 are aliases
        self._alias_relations: Set[Tuple[str, str]] = set()
    
    def add_aliases(self, function_name: str, var_name: str, alias_set: List[Dict[str, Any]]):
        """
        Add aliases for a variable in a specific function.
        
        Args:
            function_name: Name of the function
            var_name: Base variable name
            alias_set: List of alias entries from get_alias_set
        """
        if not alias_set:
            return
        
        # Extract all alias names
        alias_names = {entry["name"] for entry in alias_set}
        
        # Add to alias sources
        source_info = {
            "function": function_name,
            "var_name": var_name,
            "aliases": alias_names
        }
        self._alias_sources[var_name].append(source_info)
        
        # Update alias sets - merge all aliases
        for alias_name in alias_names:
            self._aliases[var_name].add(alias_name)
            self._aliases[alias_name].add(var_name)
            # Add bidirectional relationship
            if var_name < alias_name:
                self._alias_relations.add((var_name, alias_name))
            else:
                self._alias_relations.add((alias_name, var_name))
        
        # Merge transitive aliases
        self._merge_transitive_aliases(var_name)
    
    def _merge_transitive_aliases(self, var_name: str):
        """Merge transitive aliases (if A=B and B=C, then A=C)."""
        changed = True
        while changed:
            changed = False
            current_aliases = self._aliases[var_name].copy()
            for alias in current_aliases:
                # Get aliases of this alias
                alias_aliases = self._aliases[alias]
                for alias_alias in alias_aliases:
                    if alias_alias not in self._aliases[var_name]:
                        self._aliases[var_name].add(alias_alias)
                        self._aliases[alias_alias].add(var_name)
                        changed = True
    
    def merge_aliases(self, var1: str, var2: str):
        """Explicitly merge two variables as aliases."""
        if var1 == var2:
            return
        
        self._aliases[var1].add(var2)
        self._aliases[var2].add(var1)
        
        # Merge all aliases of var1 and var2
        for alias1 in self._aliases[var1]:
            self._aliases[var2].add(alias1)
            self._aliases[alias1].add(var2)
        
        for alias2 in self._aliases[var2]:
            self._aliases[var1].add(alias2)
            self._aliases[alias2].add(var1)
        
        # Add relation
        if var1 < var2:
            self._alias_relations.add((var1, var2))
        else:
            self._alias_relations.add((var2, var1))
    
    def get_aliases(self, var_name: str) -> Set[str]:
        """Get all aliases for a variable."""
        return self._aliases[var_name].copy()
    
    def validate_alias(self, var_name: str, target_var: str) -> bool:
        """
        Check if target_var is an alias of var_name.
        
        Args:
            var_name: Source variable name
            target_var: Target variable name to check
            
        Returns:
            True if target_var is an alias of var_name
        """
        if var_name == target_var:
            return True
        
        return target_var in self._aliases[var_name]
    
    def find_aliases_in_set(self, var_name: str, alias_set: List[Dict[str, Any]]) -> List[str]:
        """
        Find which variables in alias_set are aliases of var_name.
        
        Args:
            var_name: Variable name to check
            alias_set: List of alias entries
            
        Returns:
            List of variable names from alias_set that are aliases of var_name
        """
        result = []
        var_aliases = self.get_aliases(var_name)
        var_aliases.add(var_name)  # Include self
        
        for entry in alias_set:
            entry_name = entry.get("name", "")
            if entry_name in var_aliases:
                result.append(entry_name)
        
        return result


@dataclass
class FunctionAnalysisNode:
    """Represents a single function's analysis context in the analysis tree."""
    
    node_id: str
    function_name: str
    start_location: str
    eq_position: Optional[int] = None
    arg_index: Optional[int] = None
    cfg: Optional[Dict[str, Any]] = None
    alias_set: List[Dict[str, Any]] = field(default_factory=list)
    paths: List[List[Dict[str, Any]]] = field(default_factory=list)
    path_analysis_results: List[Dict[str, Any]] = field(default_factory=list)
    children: List['FunctionAnalysisNode'] = field(default_factory=list)
    parent: Optional['FunctionAnalysisNode'] = None
    analysis_status: str = "pending"  # "pending", "analyzing", "completed", "terminated"
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)  # Additional metadata (e.g., source path IDs)
    
    def add_child(self, child: 'FunctionAnalysisNode'):
        """Add a child node."""
        child.parent = self
        self.children.append(child)
    
    def is_terminal(self) -> bool:
        """Check if this node represents a terminal state (no further analysis needed)."""
        if not self.path_analysis_results:
            return False
        
        terminal_classifications = {"Leak", "NullPointer", "Unreachable"}
        for result in self.path_analysis_results:
            classification = result.get("classification")
            if classification not in terminal_classifications:
                return False
        
        return True


class CrossFunctionMemoryFlowAnalyzer:
    """
    Main analyzer that coordinates cross-function memory flow analysis.
    Integrates CFG building, alias table construction, and path analysis.
    """
    
    def __init__(self, client=None, model_name=None):
        self.client = client
        self.model_name = model_name
        self.global_alias_table = GlobalAliasTable()
        self.root_node: Optional[FunctionAnalysisNode] = None
        self.all_nodes: List[FunctionAnalysisNode] = []
        self._node_counter = 0
    
    def _generate_node_id(self) -> str:
        """Generate a unique node ID."""
        self._node_counter += 1
        return f"node_{self._node_counter}"
    
    def add_function_analysis_from_location(self, location: str, eq_position: int) -> FunctionAnalysisNode:
        """
        Add a function analysis starting point from a location and eq_position.
        This creates a root node for analyzing a single function's memory flow.
        
        Args:
            location: Source location in format 'file.c:line'
            eq_position: Column index of '=' sign
            
        Returns:
            The created root node for this function analysis
        """
        # Find current function
        func_info = analysis_operators.find_current_function(location)
        if not func_info or func_info.get("error"):
            raise ValueError(f"Could not find function for location {location}")
        
        function_name = func_info.get("function_name")
        
        # Create root node for this function analysis
        root = FunctionAnalysisNode(
            node_id=self._generate_node_id(),
            function_name=function_name,
            start_location=location,
            eq_position=eq_position
        )
        
        # If this is the first node, set it as the main root
        if self.root_node is None:
            self.root_node = root
        
        self.all_nodes.append(root)
        
        return root
    
    def add_function_analysis_from_formal_arg(self, function_name: str, arg_index: int) -> FunctionAnalysisNode:
        """
        Add a function analysis starting point from a function's formal parameter.
        This creates a root node for analyzing a single function's memory flow starting from a parameter.
        
        Args:
            function_name: Name of the function
            arg_index: Index of the parameter (0-based)
            
        Returns:
            The created root node for this function analysis
        """
        # Find function body
        func_info = analysis_operators.find_function_body(function_name)
        if not func_info or func_info.get("error"):
            raise ValueError(f"Could not find function body for {function_name}")
        
        # Determine start location (function start line)
        start_line = func_info.get("start_line", 0)
        filename = func_info.get("filename", "")
        start_location = f"{filename}:{start_line}"
        
        # Create root node for this function analysis
        root = FunctionAnalysisNode(
            node_id=self._generate_node_id(),
            function_name=function_name,
            start_location=start_location,
            arg_index=arg_index
        )
        
        # If this is the first node, set it as the main root
        if self.root_node is None:
            self.root_node = root
        
        self.all_nodes.append(root)
        
        return root
    
    def add_function_analysis_from_actual_arg(self, location: str, callee_function_name: str, arg_index: int) -> FunctionAnalysisNode:
        """
        Add a function analysis starting point from an actual function call location.
        This creates a root node for analyzing a single function's memory flow starting from a call argument.
        
        Args:
            location: Call location (in the caller function)
            callee_function_name: Name of the called function
            arg_index: Index of the argument (0-based)
            
        Returns:
            The created root node for this function analysis
            
        Note:
            Implementation is left empty as requested.
        """
        # TODO: Implement this method
        raise NotImplementedError("add_function_analysis_from_actual_arg is not yet implemented")
    
    @classmethod
    def from_location(cls, location: str, eq_position: int, client=None, model_name=None) -> 'CrossFunctionMemoryFlowAnalyzer':
        """
        Convenience factory method: Create analyzer and add a function analysis from location.
        This is a shortcut that creates an analyzer and immediately adds a root node.
        
        Args:
            location: Source location in format 'file.c:line'
            eq_position: Column index of '=' sign
            client: LLM client
            model_name: LLM model name
            
        Returns:
            CrossFunctionMemoryFlowAnalyzer with a root node set
        """
        analyzer = cls(client, model_name)
        analyzer.add_function_analysis_from_location(location, eq_position)
        return analyzer
    
    @classmethod
    def from_formal_function_arg(cls, function_name: str, arg_index: int, client=None, model_name=None) -> 'CrossFunctionMemoryFlowAnalyzer':
        """
        Convenience factory method: Create analyzer and add a function analysis from formal parameter.
        This is a shortcut that creates an analyzer and immediately adds a root node.
        
        Args:
            function_name: Name of the function
            arg_index: Index of the parameter (0-based)
            client: LLM client
            model_name: LLM model name
            
        Returns:
            CrossFunctionMemoryFlowAnalyzer with a root node set
        """
        analyzer = cls(client, model_name)
        analyzer.add_function_analysis_from_formal_arg(function_name, arg_index)
        return analyzer
    
    @classmethod
    def from_actual_function_arg(cls, location: str, callee_function_name: str, arg_index: int, client=None, model_name=None) -> 'CrossFunctionMemoryFlowAnalyzer':
        """
        Convenience factory method: Create analyzer and add a function analysis from actual call argument.
        This is a shortcut that creates an analyzer and immediately adds a root node.
        
        Args:
            location: Call location (in the caller function)
            callee_function_name: Name of the called function
            arg_index: Index of the argument (0-based)
            client: LLM client
            model_name: LLM model name
            
        Returns:
            CrossFunctionMemoryFlowAnalyzer with a root node set
            
        Note:
            Implementation is left empty as requested.
        """
        analyzer = cls(client, model_name)
        analyzer.add_function_analysis_from_actual_arg(location, callee_function_name, arg_index)
        return analyzer
    
    def analyze(self, start_node: Optional[FunctionAnalysisNode] = None) -> List[FunctionAnalysisNode]:
        """
        Execute the complete cross-function analysis.
        Can analyze from a specific node or from the root node.
        
        Args:
            start_node: Optional node to start analysis from. If None, uses root_node.
        
        Returns:
            List of all analysis nodes (tree structure)
        """
        target_node = start_node or self.root_node
        if not target_node:
            raise ValueError("No root node set. Use add_function_analysis_* methods or factory methods to create analyzer.")
        
        # Analyze starting from target node
        self._analyze_node(target_node)
        
        return self.all_nodes
    
    def analyze_function(self, node: FunctionAnalysisNode) -> FunctionAnalysisNode:
        """
        Analyze a single function node without automatically continuing to child nodes.
        This allows for more controlled analysis flow.
        
        Args:
            node: The function node to analyze
            
        Returns:
            The analyzed node
        """
        return self._analyze_node(node)
    
    def _analyze_node(self, node: FunctionAnalysisNode) -> FunctionAnalysisNode:
        """
        Analyze a single function node.
        
        Args:
            node: Node to analyze
            
        Returns:
            Analyzed node
        """
        if node.analysis_status != "pending":
            return node
        
        node.analysis_status = "analyzing"
        logger.info(f"Analyzing node {node.node_id}: {node.function_name}")
        
        try:
            # 1. Build CFG and generate paths
            cfg, paths = self._build_cfg_and_paths(node)
            node.cfg = cfg
            node.paths = paths
            
            if not paths:
                logger.warning(f"No paths found for {node.function_name}")
                node.analysis_status = "terminated"
                return node
            
            # 2. Build alias set
            alias_set = self._build_alias_set(node)
            node.alias_set = alias_set
            
            # 3. Update global alias table
            self._update_global_alias_table(node)
            
            # 4. Convert paths format and run path analysis
            path_analysis_results = self._run_path_analysis(node)
            node.path_analysis_results = path_analysis_results
            
            # 5. Extract next functions and create child nodes
            next_functions = self._extract_next_functions(node)
            if next_functions:
                child_nodes = self._create_child_nodes(node, next_functions)
                for child in child_nodes:
                    node.add_child(child)
                    self.all_nodes.append(child)
                    # Recursively analyze children
                    self._analyze_node(child)
            
            node.analysis_status = "completed"
            
        except Exception as e:
            logger.exception(f"Error analyzing node {node.node_id}: {e}")
            node.analysis_status = "terminated"
        
        return node
    
    def _extract_next_functions(self, node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Extract all possible next functions from path analysis results.
        Supports multiple paths pointing to different next functions (multi-path forking).
        
        Args:
            node: Analysis node
            
        Returns:
            List of next function information dicts (may contain duplicates - will be deduplicated in _create_child_nodes)
        """
        next_functions = []
        seen_functions = set()  # Track to avoid exact duplicates
        
        for result in node.path_analysis_results:
            classification = result.get("classification")
            key_operation = result.get("key_operation")
            path_id = result.get("path_id")
            
            if classification == "HandledByCallee":
                next_func = self._handle_handled_by_callee(result, key_operation)
                if next_func:
                    # Create a unique key for this next function
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id  # Track which path led here
                        next_functions.append(next_func)
            
            elif classification == "ReturnedAsReturnValue":
                next_func = self._handle_returned_as_return_value(result, node)
                if next_func:
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id
                        next_functions.append(next_func)
            
            elif classification == "ReturnedAsPointerParameter":
                next_func = self._handle_returned_as_pointer_parameter(result, node)
                if next_func:
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id
                        next_functions.append(next_func)
            
            # Leak, NullPointer, Unreachable are terminal - no next function
        
        return next_functions
    
    def _handle_handled_by_callee(self, result: Dict[str, Any], key_operation: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Handle HandledByCallee classification.
        
        Args:
            result: Path analysis result
            key_operation: Key operation information
            
        Returns:
            Next function information dict or None
        """
        if not key_operation:
            return None
        
        callee_function_name = key_operation.get("callee_function_name")
        source_location = key_operation.get("source_location")
        
        if not callee_function_name or not source_location:
            return None
        
        # Extract argument information from key_operation
        # The code_line should contain the function call
        code_line = key_operation.get("code_line", "")
        if not code_line:
            return None
        
        # Try to extract argument index from the call
        # We need to find which argument position corresponds to the tracked variable
        # This requires parsing the function call and matching arguments
        arg_index = self._extract_argument_index_from_call(code_line, source_location, callee_function_name)
        
        return {
            "type": "callee",
            "function_name": callee_function_name,
            "source_location": source_location,
            "arg_index": arg_index
        }
    
    def _extract_argument_index_from_call(self, code_line: str, location: str, function_name: str) -> Optional[int]:
        """
        Extract the argument index from a function call that corresponds to the tracked variable.
        
        This is a simplified implementation. A more sophisticated version would:
        1. Parse the function call to get all arguments
        2. Match the tracked variable/alias with the arguments
        3. Return the index of the matching argument
        
        Args:
            code_line: Code line containing the function call
            location: Location of the call
            function_name: Name of the called function
            
        Returns:
            Argument index (0-based) or None if cannot determine
        """
        # TODO: Implement proper argument extraction
        # For now, return None - this can be enhanced later
        # One approach: use tree-sitter to parse the call, extract arguments,
        # and match against the tracked variable/aliases
        return None
    
    def _handle_returned_as_return_value(self, result: Dict[str, Any], node: FunctionAnalysisNode) -> Optional[Dict[str, Any]]:
        """
        Handle ReturnedAsReturnValue classification.
        
        Args:
            result: Path analysis result
            node: Current analysis node
            
        Returns:
            Next function information dict or None
        """
        # Find callers of this function
        callers = analysis_operators.find_callers(node.function_name)
        if not callers:
            return None
        
        # For now, return the first caller
        # In a more sophisticated implementation, we'd analyze all callers
        # and create multiple child nodes for each caller
        caller = callers[0]
        caller_location = caller.get("location")
        
        if not caller_location:
            return None
        
        # Find the function that contains this caller location
        caller_func_info = analysis_operators.find_current_function(caller_location)
        if not caller_func_info or caller_func_info.get("error"):
            return None
        
        caller_function = caller_func_info.get("function_name")
        if not caller_function:
            return None
        
        # The return value is typically assigned to a variable or used directly
        # We need to determine where it's used in the caller
        # For now, use the caller location as the start location
        # TODO: Extract the assignment location from the caller
        
        return {
            "type": "caller",
            "function_name": caller_function,
            "source_location": caller_location,
            "arg_index": None,  # Return values are not arguments
            "is_return_value": True
        }
    
    def _handle_returned_as_pointer_parameter(self, result: Dict[str, Any], node: FunctionAnalysisNode) -> Optional[Dict[str, Any]]:
        """
        Handle ReturnedAsPointerParameter classification.
        
        Args:
            result: Path analysis result
            node: Current analysis node
            
        Returns:
            Next function information dict or None
        """
        # Similar to ReturnedAsReturnValue, but need to identify the parameter
        callers = analysis_operators.find_callers(node.function_name)
        if not callers:
            return None
        
        caller_location = callers[0].get("location")
        if not caller_location:
            return None
        
        # Find the function that contains this caller location
        caller_func_info = analysis_operators.find_current_function(caller_location)
        if not caller_func_info or caller_func_info.get("error"):
            return None
        
        caller_function = caller_func_info.get("function_name")
        if not caller_function:
            return None
        
        # Extract parameter index from key_operation
        key_operation = result.get("key_operation")
        param_index = None
        if key_operation:
            # The key_operation should contain information about which parameter
            # receives the pointer. This might be in the code_line or as a separate field
            # TODO: Implement proper parameter index extraction
            # For now, try to extract from code_line if available
            code_line = key_operation.get("code_line", "")
            if code_line:
                # Try to parse the function call to find the parameter
                # This is a placeholder - needs proper implementation
                pass
        
        return {
            "type": "caller",
            "function_name": caller_function,
            "source_location": caller_location,
            "arg_index": param_index,
            "is_pointer_parameter": True
        }
    
    def _create_child_nodes(self, parent: FunctionAnalysisNode, next_functions: List[Dict[str, Any]]) -> List[FunctionAnalysisNode]:
        """
        Create child nodes for next functions.
        Supports creating multiple child nodes for different paths (multi-path forking).
        
        Args:
            parent: Parent node
            next_functions: List of next function information (may come from different paths)
            
        Returns:
            List of child nodes (one per unique next function)
        """
        child_nodes = []
        created_nodes = {}  # Track created nodes to avoid duplicates
        
        for next_func in next_functions:
            func_type = next_func.get("type")
            function_name = next_func.get("function_name")
            source_location = next_func.get("source_location")
            arg_index = next_func.get("arg_index")
            path_id = next_func.get("source_path_id")
            
            # Create a unique key for this node
            node_key = (func_type, function_name, source_location, arg_index)
            
            if node_key in created_nodes:
                # Node already created, just add path reference
                existing_node = created_nodes[node_key]
                if path_id:
                    existing_node.source_path_ids.append(path_id)
                continue
            
            # Create new child node
            child = FunctionAnalysisNode(
                node_id=self._generate_node_id(),
                function_name=function_name,
                start_location=source_location,
                arg_index=arg_index if func_type == "callee" else None,
                eq_position=None,  # Will be determined from arg_index or source_location
                parent=parent
            )
            
            if path_id:
                child.source_path_ids = [path_id]
            
            child_nodes.append(child)
            created_nodes[node_key] = child
        
        return child_nodes
    
    def _build_cfg_and_paths(self, node: FunctionAnalysisNode) -> Tuple[Optional[Dict[str, Any]], List[List[Dict[str, Any]]]]:
        """
        Build CFG and generate paths using trace_paths_to_exit.
        
        Args:
            node: Analysis node
            
        Returns:
            Tuple of (CFG dict, list of paths)
        """
        function_name = node.function_name
        
        # Build CFG
        cfg_analyzer = FunctionCFGAnalyzer.from_function_name(function_name)
        if not cfg_analyzer:
            logger.error(f"Failed to create CFG analyzer for {function_name}")
            return None, []
        
        cfg = cfg_analyzer.build_cfg()
        if not cfg:
            logger.error(f"Failed to build CFG for {function_name}")
            return None, []
        
        # Generate paths using trace_paths_to_exit
        if node.eq_position is not None:
            # Use location + eq_position
            location = node.start_location
            eq_position = str(node.eq_position)
            paths = FunctionCFGAnalyzer.trace_paths_to_exit(
                location=location,
                eq_position=eq_position
            )
        elif node.arg_index is not None:
            # For formal parameters, we need to find the parameter location
            # This is a simplified approach - may need refinement
            func_info = analysis_operators.find_function_body(function_name)
            if func_info:
                start_line = func_info.get("start_line", 0)
                filename = func_info.get("filename", "")
                # Use function start as location, arg_index as eq_position (simplified)
                location = f"{filename}:{start_line}"
                eq_position = str(node.arg_index)
                paths = FunctionCFGAnalyzer.trace_paths_to_exit(
                    location=location,
                    eq_position=eq_position
                )
            else:
                paths = []
        else:
            logger.warning(f"No eq_position or arg_index for node {node.node_id}")
            paths = []
        
        return cfg, paths
    
    def _build_alias_set(self, node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Build alias set for the node.
        
        Args:
            node: Analysis node
            
        Returns:
            List of alias entries
        """
        if node.eq_position is not None:
            # Use get_alias_set
            alias_set = analysis_operators.get_alias_set(
                node.start_location,
                node.eq_position
            )
            return alias_set
        elif node.arg_index is not None:
            # For formal parameters, we may need a different approach
            # For now, return empty list - can be enhanced later
            logger.warning(f"Alias set for formal parameter not yet implemented for {node.function_name}")
            return []
        else:
            return []
    
    def _update_global_alias_table(self, node: FunctionAnalysisNode):
        """Update global alias table with node's alias set."""
        if not node.alias_set:
            return
        
        # Use the first alias entry as the base variable
        if node.alias_set:
            base_var = node.alias_set[0].get("name", "")
            self.global_alias_table.add_aliases(
                node.function_name,
                base_var,
                node.alias_set
            )
    
    def _convert_paths_for_agent(self, raw_paths: List[List[Dict[str, Any]]], function_name: str) -> List[Dict[str, Any]]:
        """
        Convert trace_paths_to_exit format to FunctionPathBuilderAgent expected format.
        
        The FunctionPathBuilderAgent expects paths in format:
        [{"path": [node1, node2, ...], ...}, ...]
        where each node has fields like "node", "location", "node_desc", etc.
        
        Args:
            raw_paths: Paths from trace_paths_to_exit (List[List[{"node": {...}, "edge": {...}}]])
            function_name: Function name
            
        Returns:
            List of path entries in agent format: [{"path": [nodes...]}, ...]
        """
        converted_paths = []
        
        for idx, path in enumerate(raw_paths, start=1):
            path_nodes = []
            
            for step in path:
                node_info = step.get("node", {})
                edge_info = step.get("edge")
                
                # Convert node format - match the format expected by _normalize_nodes
                # The original format has nodes with: node, location, node_desc, condition_value, etc.
                converted_node = {
                    "node": node_info.get("type", "unknown"),
                    "location": node_info.get("location", ""),
                    "condition_value": None,
                    "node_desc": ""  # Needed for branch expression extraction
                }
                
                # Handle branch nodes
                node_type = node_info.get("type", "")
                if node_type == "branch":
                    condition = node_info.get("condition")
                    if condition:
                        # Try to determine condition value from edge
                        if edge_info:
                            edge_type = edge_info.get("type", "")
                            if edge_type == "true_branch":
                                converted_node["condition_value"] = "true"
                            elif edge_type == "false_branch":
                                converted_node["condition_value"] = "false"
                        
                        # Create node_desc for expression extraction
                        # Format: {"ln": line, "cl": column, "fl": file}
                        location = node_info.get("location", "")
                        if location:
                            try:
                                file_part, line_part = location.split(":")
                                line_num = int(line_part)
                                # Try to find column from code line
                                code_line = find_code_line(location, strip_whitespace=False)
                                if code_line and condition:
                                    # Try to find condition in code line
                                    cond_idx = code_line.find(condition)
                                    if cond_idx >= 0:
                                        col_num = cond_idx + 1  # 1-based
                                    else:
                                        col_num = 1  # Default
                                else:
                                    col_num = 1
                                converted_node["node_desc"] = f'{{"ln": {line_num}, "cl": {col_num}, "fl": "{file_part}"}}'
                            except Exception as e:
                                logger.debug(f"Error creating node_desc: {e}")
                                # Fallback: create minimal node_desc
                                try:
                                    file_part, line_part = location.split(":")
                                    converted_node["node_desc"] = f'{{"ln": {line_part}, "cl": 1, "fl": "{file_part}"}}'
                                except:
                                    pass
                
                # Handle other node types - preserve statements if available
                statements = node_info.get("statements", [])
                if statements:
                    converted_node["statements"] = statements
                
                # Preserve other fields that might be useful
                if "start_line" in node_info:
                    converted_node["start_line"] = node_info["start_line"]
                if "end_line" in node_info:
                    converted_node["end_line"] = node_info["end_line"]
                
                path_nodes.append(converted_node)
            
            # Create path entry matching the format expected by FunctionPathBuilderAgent
            # The agent expects: {"path": [nodes...]} which will be normalized
            path_entry = {
                "path": path_nodes  # This matches the format in init_function_raw_path
            }
            converted_paths.append(path_entry)
        
        return converted_paths
    
    def _run_path_analysis(self, node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Run path analysis using FunctionPathBuilderAgent.
        
        Args:
            node: Analysis node
            
        Returns:
            List of path analysis results
        """
        if not node.paths:
            return []
        
        # Convert paths format
        converted_paths = self._convert_paths_for_agent(node.paths, node.function_name)
        
        if not converted_paths:
            return []
        
        # Create a custom agent that accepts pre-converted paths
        # We'll create a wrapper class that extends FunctionPathBuilderAgent
        try:
            start_location = node.start_location
            eq_position = node.eq_position or 0
            
            # Create a custom agent instance
            agent = _CustomPathBuilderAgent(
                source_location=start_location,
                eq_position=eq_position,
                client=self.client,
                model_name=self.model_name,
                pre_converted_paths=converted_paths
            )
            
            # Run analysis
            completed_paths = agent.analyze_paths()
            
            # Extract results from agent's path_data (which contains the completed paths)
            results = []
            for path_entry in agent.path_data:
                result = {
                    "path_id": path_entry.get("path_id"),
                    "classification": path_entry.get("path_classification"),
                    "reason": path_entry.get("reason"),
                    "key_operation": path_entry.get("key_operation")
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.exception(f"Error running path analysis for {node.function_name}: {e}")
            return []


class _CustomPathBuilderAgent(FunctionPathBuilderAgent):
    """
    Custom FunctionPathBuilderAgent that accepts pre-converted paths.
    This bypasses the init_function_raw_path method.
    """
    
    def __init__(self, source_location: str, eq_position: int, client=None, model_name=None, pre_converted_paths=None):
        self.source_location = source_location
        self.eq_position = eq_position
        self.client = client
        self.model_name = model_name
        self.path_data: List[Dict[str, Any]] = []
        self.path_number: Optional[int] = None
        self.svfg_nodes: List[Dict[str, Any]] = []  # Initialize SVFG nodes
        
        # Get SVFG nodes for enhanced path analysis
        try:
            self.svfg_nodes = analysis_operators.find_lvalue_key_svfgnode(
                source_location, str(eq_position)
            )
            logger.info(f"[_CustomPathBuilderAgent] Loaded {len(self.svfg_nodes)} SVFG nodes")
        except Exception as e:
            logger.warning(f"[_CustomPathBuilderAgent] Failed to fetch SVFG nodes: {e}")
            self.svfg_nodes = []
        
        # Use pre-converted paths if provided
        if pre_converted_paths:
            # Normalize the paths using _normalize_nodes (same as init_function_raw_path does)
            for idx, path_entry in enumerate(pre_converted_paths, start=1):
                path_nodes = path_entry.get("path", [])
                normalized_nodes = FunctionPathBuilderAgent._normalize_nodes(path_nodes)
                normalized_path_entry = {
                    "path_id": str(idx),
                    "path_classification": None,
                    "key_operation": None,
                    "path_node_list": normalized_nodes
                }
                self.path_data.append(normalized_path_entry)
            self.path_number = len(self.path_data)
        else:
            # Fall back to normal initialization
            if not self.init_function_raw_path(self.source_location, self.eq_position):
                raise ValueError(f"Failed to initialize raw path data for {self.source_location}")
        
        # 工具方法映射
        self.tool_method_map = {
            "complete_path": self.complete_path_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
            "read_ctag_symbol": self.read_ctag_symbol_Tool,
        }
    
    def _extract_next_functions(self, node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Extract all possible next functions from path analysis results.
        Supports multiple paths pointing to different next functions (multi-path forking).
        
        Args:
            node: Analysis node
            
        Returns:
            List of next function information dicts (may contain duplicates - will be deduplicated in _create_child_nodes)
        """
        next_functions = []
        seen_functions = set()  # Track to avoid exact duplicates
        
        for result in node.path_analysis_results:
            classification = result.get("classification")
            key_operation = result.get("key_operation")
            path_id = result.get("path_id")
            
            if classification == "HandledByCallee":
                next_func = self._handle_handled_by_callee(result, key_operation)
                if next_func:
                    # Create a unique key for this next function
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id  # Track which path led here
                        next_functions.append(next_func)
            
            elif classification == "ReturnedAsReturnValue":
                next_func = self._handle_returned_as_return_value(result, node)
                if next_func:
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id
                        next_functions.append(next_func)
            
            elif classification == "ReturnedAsPointerParameter":
                next_func = self._handle_returned_as_pointer_parameter(result, node)
                if next_func:
                    func_key = (
                        next_func.get("type"),
                        next_func.get("function_name"),
                        next_func.get("source_location"),
                        next_func.get("arg_index")
                    )
                    if func_key not in seen_functions:
                        seen_functions.add(func_key)
                        next_func["source_path_id"] = path_id
                        next_functions.append(next_func)
            
            # Leak, NullPointer, Unreachable are terminal - no next function
        
        return next_functions
    
    def _handle_handled_by_callee(self, result: Dict[str, Any], key_operation: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Handle HandledByCallee classification.
        
        Args:
            result: Path analysis result
            key_operation: Key operation information
            
        Returns:
            Next function information dict or None
        """
        if not key_operation:
            return None
        
        callee_function_name = key_operation.get("callee_function_name")
        source_location = key_operation.get("source_location")
        
        if not callee_function_name or not source_location:
            return None
        
        # Extract argument information from key_operation
        # The code_line should contain the function call
        code_line = key_operation.get("code_line", "")
        if not code_line:
            return None
        
        # Try to extract argument index from the call
        # We need to find which argument position corresponds to the tracked variable
        # This requires parsing the function call and matching arguments
        arg_index = self._extract_argument_index_from_call(code_line, source_location, callee_function_name)
        
        return {
            "type": "callee",
            "function_name": callee_function_name,
            "source_location": source_location,
            "arg_index": arg_index
        }
    
    def _extract_argument_index_from_call(self, code_line: str, location: str, function_name: str) -> Optional[int]:
        """
        Extract the argument index from a function call that corresponds to the tracked variable.
        
        This is a simplified implementation. A more sophisticated version would:
        1. Parse the function call to get all arguments
        2. Match the tracked variable/alias with the arguments
        3. Return the index of the matching argument
        
        Args:
            code_line: Code line containing the function call
            location: Location of the call
            function_name: Name of the called function
            
        Returns:
            Argument index (0-based) or None if cannot determine
        """
        # TODO: Implement proper argument extraction
        # For now, return None - this can be enhanced later
        # One approach: use tree-sitter to parse the call, extract arguments,
        # and match against the tracked variable/aliases
        return None
    
    def _handle_returned_as_return_value(self, result: Dict[str, Any], node: FunctionAnalysisNode) -> Optional[Dict[str, Any]]:
        """
        Handle ReturnedAsReturnValue classification.
        
        Args:
            result: Path analysis result
            node: Current analysis node
            
        Returns:
            Next function information dict or None
        """
        # Find callers of this function
        callers = analysis_operators.find_callers(node.function_name)
        if not callers:
            return None
        
        # For now, return the first caller
        # In a more sophisticated implementation, we'd analyze all callers
        # and create multiple child nodes for each caller
        caller = callers[0]
        caller_location = caller.get("location")
        
        if not caller_location:
            return None
        
        # Find the function that contains this caller location
        caller_func_info = analysis_operators.find_current_function(caller_location)
        if not caller_func_info or caller_func_info.get("error"):
            return None
        
        caller_function = caller_func_info.get("function_name")
        if not caller_function:
            return None
        
        # The return value is typically assigned to a variable or used directly
        # We need to determine where it's used in the caller
        # For now, use the caller location as the start location
        # TODO: Extract the assignment location from the caller
        
        return {
            "type": "caller",
            "function_name": caller_function,
            "source_location": caller_location,
            "arg_index": None,  # Return values are not arguments
            "is_return_value": True
        }
    
    def _handle_returned_as_pointer_parameter(self, result: Dict[str, Any], node: FunctionAnalysisNode) -> Optional[Dict[str, Any]]:
        """
        Handle ReturnedAsPointerParameter classification.
        
        Args:
            result: Path analysis result
            node: Current analysis node
            
        Returns:
            Next function information dict or None
        """
        # Similar to ReturnedAsReturnValue, but need to identify the parameter
        callers = analysis_operators.find_callers(node.function_name)
        if not callers:
            return None
        
        caller_location = callers[0].get("location")
        if not caller_location:
            return None
        
        # Find the function that contains this caller location
        caller_func_info = analysis_operators.find_current_function(caller_location)
        if not caller_func_info or caller_func_info.get("error"):
            return None
        
        caller_function = caller_func_info.get("function_name")
        if not caller_function:
            return None
        
        # Extract parameter index from key_operation
        key_operation = result.get("key_operation")
        param_index = None
        if key_operation:
            # The key_operation should contain information about which parameter
            # receives the pointer. This might be in the code_line or as a separate field
            # TODO: Implement proper parameter index extraction
            # For now, try to extract from code_line if available
            code_line = key_operation.get("code_line", "")
            if code_line:
                # Try to parse the function call to find the parameter
                # This is a placeholder - needs proper implementation
                pass
        
        return {
            "type": "caller",
            "function_name": caller_function,
            "source_location": caller_location,
            "arg_index": param_index,
            "is_pointer_parameter": True
        }
    
    def _create_child_nodes(self, parent: FunctionAnalysisNode, next_functions: List[Dict[str, Any]]) -> List[FunctionAnalysisNode]:
        """
        Create child nodes for next functions.
        Supports creating multiple child nodes for different paths (multi-path forking).
        
        Args:
            parent: Parent node
            next_functions: List of next function information (may come from different paths)
            
        Returns:
            List of child nodes (one per unique next function)
        """
        child_nodes = []
        created_nodes = {}  # Track created nodes to avoid duplicates
        
        for next_func_info in next_functions:
            function_name = next_func_info.get("function_name")
            source_location = next_func_info.get("source_location")
            arg_index = next_func_info.get("arg_index")
            
            if not function_name:
                continue
            
            # Create a unique key for this next function
            node_key = (function_name, source_location, arg_index)
            
            # Skip if we've already created a node for this function
            if node_key in created_nodes:
                continue
            
            # Validate alias before creating child node
            if not self._validate_alias_for_next_function(parent, next_func_info):
                logger.warning(f"Alias validation failed for {function_name}, skipping")
                continue
            
            # Create child node
            child = FunctionAnalysisNode(
                node_id=self._generate_node_id(),
                function_name=function_name,
                start_location=source_location or "",
                arg_index=arg_index
            )
            
            # Store metadata about which path(s) led to this child
            child.metadata = {
                "source_path_ids": [next_func_info.get("source_path_id")],
                "next_func_type": next_func_info.get("type")
            }
            
            child_nodes.append(child)
            created_nodes[node_key] = child
        
        return child_nodes
    
    def _validate_alias_for_next_function(self, parent: FunctionAnalysisNode, next_func_info: Dict[str, Any]) -> bool:
        """
        Validate that the target variable in next function is in the global alias table.
        
        Args:
            parent: Parent analysis node
            next_func_info: Next function information
            
        Returns:
            True if validation passes
        """
        # Get parent's tracked variable
        if not parent.alias_set:
            logger.warning(f"No alias set for parent node {parent.node_id}")
            return False
        
        parent_var = parent.alias_set[0].get("name", "")
        if not parent_var:
            logger.warning(f"No base variable in alias set for parent node {parent.node_id}")
            return False
        
        # Get all aliases for the parent variable
        parent_aliases = self.global_alias_table.get_aliases(parent_var)
        parent_aliases.add(parent_var)  # Include the variable itself
        
        # For callee functions, check if the argument corresponds to an alias
        if next_func_info.get("type") == "callee":
            arg_index = next_func_info.get("arg_index")
            if arg_index is not None:
                # TODO: Get the actual parameter name from the callee function
                # and check if it matches any alias
                # For now, we assume validation passes if we have aliases
                return len(parent_aliases) > 0
            else:
                # If we can't determine arg_index, still allow if we have aliases
                return len(parent_aliases) > 0
        
        # For caller functions (return value or pointer parameter)
        # The validation is more complex - we need to check if the return value
        # or parameter in the caller matches our aliases
        # For now, basic validation
        return len(parent_aliases) > 0


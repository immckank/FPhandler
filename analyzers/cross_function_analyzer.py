"""
Cross-function memory flow analyzer that integrates CFG building, alias table construction,
and path analysis across multiple functions.
"""

import copy
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

import analysis_operators
from function_ast_cfg import FunctionCFGAnalyzer
from analyzers.path_builder_agent import FunctionPathBuilderAgent
from utils import find_code_line, extract_lhs_variable, parse_code_line, safe_load_json
from prompts import VALUE_PATH_PROMPT, ASSUMPTION_PROMPT

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
    analysis_mode: str  # "lvar", "formal_arg", "actual_arg"
    eq_position: Optional[int] = None
    arg_index: Optional[int] = None
    callee_function_name: Optional[str] = None  # For actual_arg mode: name of the called function
    tracked_variable: Optional[str] = None  # Variable name being tracked in this analysis
    cfg: Optional[Dict[str, Any]] = None
    alias_set: List[Dict[str, Any]] = field(default_factory=list)
    paths: List[Dict[str, Any]] = field(default_factory=list)  # Direct storage of trace_paths_to_exit return format
    path_analysis_results: List[Dict[str, Any]] = field(default_factory=list)
    children: List['FunctionAnalysisNode'] = field(default_factory=list)
    parent: Optional['FunctionAnalysisNode'] = None
    analysis_status: str = "pending"  # "pending", "analyzing", "completed", "terminated"
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)  # Additional metadata (e.g., source path IDs)
    previous_analysis_paths: List[Dict[str, Any]] = field(default_factory=list)  # Previous analysis path chain (single path from root to current node)
    
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
    
    @staticmethod
    def _determine_analysis_mode(eq_position: Optional[int], arg_index: Optional[int], callee_function_name: Optional[str]) -> str:
        """Determine analysis mode based on node properties."""
        if eq_position is not None:
            return "lvar"
        elif arg_index is not None:
            if callee_function_name is not None:
                return "actual_arg"
            else:
                return "formal_arg"
        else:
            # Default fallback
            return "lvar"
    
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
        analysis_mode = self._determine_analysis_mode(eq_position, None, None)
        root = FunctionAnalysisNode(
            node_id=self._generate_node_id(),
            function_name=function_name,
            start_location=location,
            analysis_mode=analysis_mode,
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
        analysis_mode = self._determine_analysis_mode(None, arg_index, None)
        root = FunctionAnalysisNode(
            node_id=self._generate_node_id(),
            function_name=function_name,
            start_location=start_location,
            analysis_mode=analysis_mode,
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
        """
        # Verify that the callee function exists
        func_info = analysis_operators.find_function_body(callee_function_name)
        if not func_info or func_info.get("error"):
            raise ValueError(f"Could not find function body for {callee_function_name}")
        
        # Create root node for this function analysis
        # Note: function_name is the callee function being analyzed
        # start_location is the call location in the caller function
        analysis_mode = self._determine_analysis_mode(None, arg_index, callee_function_name)
        root = FunctionAnalysisNode(
            node_id=self._generate_node_id(),
            function_name=callee_function_name,
            start_location=location,
            analysis_mode=analysis_mode,
            arg_index=arg_index,
            callee_function_name=callee_function_name
        )
        
        # If this is the first node, set it as the main root
        if self.root_node is None:
            self.root_node = root
        
        self.all_nodes.append(root)
        
        return root
    
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
        
        # Output analysis results including key_operation locations
        self._output_analysis_results()
        
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
            # Step 1: Extract tracked variable based on analysis mode
            if not node.tracked_variable:
                node.tracked_variable = self._extract_tracked_variable(node)
            
            # Step 2: Build CFG and generate paths
            cfg, paths = self._build_cfg_and_paths(node)
            node.cfg = cfg
            node.paths = paths
            
            if not paths:
                logger.warning(f"No paths found for {node.function_name}")
                node.analysis_status = "terminated"
                return node
            
            # Step 2 (continued): Build alias set
            alias_set = self._build_alias_set(node)
            node.alias_set = alias_set
            
            # 3. Update global alias table
            self._update_global_alias_table(node)
            
            # 4. Convert paths format and run path analysis
            path_analysis_results = self._run_path_analysis(node)
            node.path_analysis_results = path_analysis_results
            
            # Output this node's results IMMEDIATELY after path analysis, before analyzing children
            # This ensures the output is visible before child node analysis starts
            self._output_node_results(node)
            
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
                next_func_list = self._handle_returned_as_pointer_parameter(result, node)
                for next_func in next_func_list:
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
    
    def _handle_returned_as_pointer_parameter(self, result: Dict[str, Any], node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Handle ReturnedAsPointerParameter classification.
        
        处理流程：
        1. 从 key_operation 中提取 code_line（赋值语句）
        2. 从 code_line 中提取左侧变量名（LHS variable），即接收指针的参数名
        3. 在当前函数声明中查找该参数名对应的参数索引（param_index）
        4. 查找所有调用当前函数的调用者位置（callers）
        5. 为每个调用者创建一个 next_func 节点，类型为 "callee"
           这些子节点将用于继续分析调用者函数中对应参数的内存流
        
        Args:
            result: Path analysis result，包含 classification 和 key_operation
            node: Current analysis node，当前正在分析的函数节点
            
        Returns:
            List of next function information dicts (one for each caller location)
            每个 dict 包含：
            - type: "callee"
            - function_name: 调用者函数名
            - callee_function_name: 被调用函数名（即当前 node.function_name）
            - source_location: 调用位置
            - arg_index: 参数索引（在调用者函数中对应参数的位置）
            - is_pointer_parameter: True
        """
        logger.debug(f"[ReturnedAsPointerParameter] Starting processing for function: {node.function_name}")
        
        # 1. Extract left-hand side variable name from key_operation
        key_operation = result.get("key_operation")
        if not key_operation:
            logger.warning(f"[ReturnedAsPointerParameter] No key_operation in result for {node.function_name}")
            return []
        
        logger.debug(f"[ReturnedAsPointerParameter] Key operation: {key_operation}")
        
        code_line = key_operation.get("code_line", "")
        if not code_line:
            logger.warning(f"[ReturnedAsPointerParameter] No code_line in key_operation for {node.function_name}")
            return []
        
        logger.debug(f"[ReturnedAsPointerParameter] Code line: {code_line}")
        
        # Extract left-hand side variable name from assignment statement
        lhs_var_name = extract_lhs_variable(code_line)
        if not lhs_var_name:
            logger.warning(f"[ReturnedAsPointerParameter] Could not extract LHS variable from code_line: {code_line}")
            return []
        
        logger.debug(f"[ReturnedAsPointerParameter] Extracted LHS variable name: '{lhs_var_name}'")
        
        # 2. Find parameter index by name in current function declaration
        logger.debug(f"[ReturnedAsPointerParameter] Searching for parameter '{lhs_var_name}' in function '{node.function_name}' declaration")
        param_index = analysis_operators._find_parameter_index_by_name(node.function_name, lhs_var_name)
        if param_index is None:
            logger.warning(f"[ReturnedAsPointerParameter] Could not find parameter index for '{lhs_var_name}' in function {node.function_name}")
            return []
        
        logger.debug(f"[ReturnedAsPointerParameter] Found parameter index: {param_index} for parameter '{lhs_var_name}' in function '{node.function_name}'")
        
        # 3. Get all caller locations
        logger.debug(f"[ReturnedAsPointerParameter] Finding all callers of function '{node.function_name}'")
        callers = analysis_operators.find_callers(node.function_name)
        if not callers:
            logger.debug(f"[ReturnedAsPointerParameter] No callers found for {node.function_name}")
            return []
        
        logger.debug(f"[ReturnedAsPointerParameter] Found {len(callers)} caller(s) for function '{node.function_name}'")
        
        # 4. Create next_func dict for each caller location
        next_functions = []
        for idx, caller in enumerate(callers):
            logger.debug(f"[ReturnedAsPointerParameter] Processing caller {idx + 1}/{len(callers)}: {caller}")
            
            caller_location = caller.get("location")
            if not caller_location:
                logger.debug(f"[ReturnedAsPointerParameter] Caller {idx + 1} has no location, skipping")
                continue
            
            logger.debug(f"[ReturnedAsPointerParameter] Caller location: {caller_location}")
            
            # Find the function that contains this caller location
            caller_func_info = analysis_operators.find_current_function(caller_location)
            if not caller_func_info or caller_func_info.get("error"):
                logger.debug(f"[ReturnedAsPointerParameter] Could not find function for caller location {caller_location}, skipping")
                continue
            
            caller_function = caller_func_info.get("function_name")
            if not caller_function:
                logger.debug(f"[ReturnedAsPointerParameter] Caller function name is empty for location {caller_location}, skipping")
                continue
            
            logger.debug(f"[ReturnedAsPointerParameter] Caller function: '{caller_function}' at location {caller_location}")
            
            # Create next_func dict with type "callee" (for actual_arg mode)
            next_func = {
                "type": "callee",
                "function_name": caller_function,  # Caller function name
                "callee_function_name": node.function_name,  # Called function name
                "source_location": caller_location,
                "arg_index": param_index,
                "is_pointer_parameter": True
            }
            next_functions.append(next_func)
            logger.debug(f"[ReturnedAsPointerParameter] Created next_func: type=callee, function_name={caller_function}, "
                        f"callee_function_name={node.function_name}, source_location={caller_location}, arg_index={param_index}")
        
        logger.debug(f"[ReturnedAsPointerParameter] Completed processing. Created {len(next_functions)} next function node(s) for function '{node.function_name}'")
        return next_functions
    
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
                if path_id and "source_path_ids" in existing_node.metadata:
                    existing_node.metadata["source_path_ids"].append(path_id)
                continue
            
            # Build previous analysis path for this child node
            # Find the specific path analysis result that triggered this child node
            parent_path_result = None
            if path_id and parent.path_analysis_results:
                for result in parent.path_analysis_results:
                    if str(result.get("path_id")) == str(path_id):
                        parent_path_result = result
                        break
            
            # Extract condition branches from the parent path
            # The new path data format from trace_paths_to_exit contains conditions directly
            path_conditions = []
            if path_id and parent.paths:
                try:
                    # path_id is typically a string like "1", "2", etc., representing the index
                    path_idx = int(str(path_id)) - 1  # Convert to 0-based index
                    if 0 <= path_idx < len(parent.paths):
                        parent_path = parent.paths[path_idx]
                        # New format: parent_path is a dict with "steps", "conditions", etc.
                        if isinstance(parent_path, dict):
                            # Use conditions directly from the path data (already extracted by trace_paths_to_exit)
                            conditions = parent_path.get("conditions", [])
                            if conditions:
                                path_conditions = conditions
                            else:
                                # Fallback: extract from steps if conditions not available
                                steps = parent_path.get("steps", [])
                                for step in steps:
                                    if not isinstance(step, dict):
                                        continue
                                    node_info = step.get("node", {})
                                    edge_info = step.get("edge")
                                    if not node_info:
                                        continue
                                    
                                    node_type = node_info.get("type", "")
                                    edge_type = edge_info.get("type", "") if edge_info else ""
                                    
                                    # Check if this step represents a branch
                                    is_branch = (node_type == "branch") or (edge_type in ["true_branch", "false_branch", "switch_case", "loop_body"])
                                    
                                    if is_branch:
                                        condition = node_info.get("condition", "")
                                        if not condition and edge_info:
                                            condition = edge_info.get("condition", "")
                                        
                                        location = node_info.get("location", "")
                                        condition_value = None
                                        
                                        if edge_info:
                                            if edge_type == "true_branch":
                                                condition_value = "true"
                                            elif edge_type == "false_branch":
                                                condition_value = "false"
                                            elif edge_type == "switch_case":
                                                case_value = edge_info.get("condition", "")
                                                if case_value:
                                                    condition_value = case_value
                                        
                                        expression = condition
                                        if not expression and location:
                                            try:
                                                code_line = find_code_line(location, strip_whitespace=False)
                                                if code_line:
                                                    expression = code_line.strip()
                                            except Exception as e:
                                                logger.debug(f"Failed to extract branch expression from code line: {e}")
                                        
                                        if expression or condition:
                                            path_conditions.append({
                                                "location": location,
                                                "expression": expression or condition,
                                                "condition_value": condition_value,
                                                "code_line": find_code_line(location) if location else ""
                                            })
                        else:
                            # Old format fallback: treat as list of steps
                            for step in parent_path:
                                if not isinstance(step, dict):
                                    continue
                                node_info = step.get("node", {})
                                edge_info = step.get("edge")
                                if not node_info:
                                    continue
                                
                                node_type = node_info.get("type", "")
                                edge_type = edge_info.get("type", "") if edge_info else ""
                                
                                is_branch = (node_type == "branch") or (edge_type in ["true_branch", "false_branch", "switch_case", "loop_body"])
                                
                                if is_branch:
                                    condition = node_info.get("condition", "")
                                    if not condition and edge_info:
                                        condition = edge_info.get("condition", "")
                                    
                                    location = node_info.get("location", "")
                                    condition_value = None
                                    
                                    if edge_info:
                                        if edge_type == "true_branch":
                                            condition_value = "true"
                                        elif edge_type == "false_branch":
                                            condition_value = "false"
                                        elif edge_type == "switch_case":
                                            case_value = edge_info.get("condition", "")
                                            if case_value:
                                                condition_value = case_value
                                    
                                    expression = condition
                                    if not expression and location:
                                        try:
                                            code_line = find_code_line(location, strip_whitespace=False)
                                            if code_line:
                                                expression = code_line.strip()
                                        except Exception as e:
                                            logger.debug(f"Failed to extract branch expression from code line: {e}")
                                    
                                    if expression or condition:
                                        path_conditions.append({
                                            "location": location,
                                            "expression": expression or condition,
                                            "condition_value": condition_value,
                                            "code_line": find_code_line(location) if location else ""
                                        })
                except (ValueError, IndexError, TypeError) as e:
                    logger.debug(f"Failed to extract path conditions for path_id {path_id}: {e}")
            
            # Build previous analysis path chain
            previous_analysis_paths = []
            if parent.previous_analysis_paths:
                # Copy parent's previous paths
                previous_analysis_paths = copy.deepcopy(parent.previous_analysis_paths)
            
            # Add parent node's current path analysis result to the chain
            if parent_path_result:
                # Build analysis path entry for parent node
                parent_path_entry = {
                    "function_name": parent.function_name,
                    "start_location": parent.start_location,
                    "path_id": parent_path_result.get("path_id"),
                    "classification": parent_path_result.get("classification"),
                    "key_operation": parent_path_result.get("key_operation"),
                    "reason": parent_path_result.get("reason"),
                    "eq_position": parent.eq_position,
                    "arg_index": parent.arg_index,
                    "callee_function_name": parent.callee_function_name,
                    "conditions": path_conditions  # Add condition branches
                }
                previous_analysis_paths.append(parent_path_entry)
            
            # Create new child node
            # For callee type, this is an actual_arg mode analysis
            # function_name should be the caller function, callee_function_name should be the called function
            callee_function_name = next_func.get("callee_function_name")
            if func_type == "callee":
                # For actual_arg mode: function_name is the caller, callee_function_name is the called function
                child_analysis_mode = self._determine_analysis_mode(None, arg_index, callee_function_name if callee_function_name else function_name)
                child = FunctionAnalysisNode(
                    node_id=self._generate_node_id(),
                    function_name=function_name,  # Caller function name
                    start_location=source_location,
                    analysis_mode=child_analysis_mode,
                    arg_index=arg_index,
                    callee_function_name=callee_function_name if callee_function_name else function_name,
                    eq_position=None,  # Will be determined from arg_index or source_location
                    parent=parent,
                    previous_analysis_paths=previous_analysis_paths
                )
            else:
                # For other types (caller), use original logic
                child_analysis_mode = self._determine_analysis_mode(None, None, None)
                child = FunctionAnalysisNode(
                    node_id=self._generate_node_id(),
                    function_name=function_name,
                    start_location=source_location,
                    analysis_mode=child_analysis_mode,
                    arg_index=None,
                    callee_function_name=None,
                    eq_position=None,
                    parent=parent,
                    previous_analysis_paths=previous_analysis_paths
                )
            
            if path_id:
                if "source_path_ids" not in child.metadata:
                    child.metadata["source_path_ids"] = []
                child.metadata["source_path_ids"].append(path_id)
            
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
        # Determine mode based on node properties:
        # - lvar mode: eq_position is not None
        # - formal_arg mode: arg_index is not None and callee_function_name is None
        # - actual_arg mode: arg_index is not None and callee_function_name is not None
        if node.eq_position is not None:
            # lvar mode: Use location + eq_position
            location = node.start_location
            eq_position = str(node.eq_position)
            paths = FunctionCFGAnalyzer.trace_paths_to_exit(
                location=location,
                eq_position=eq_position
            )
        elif node.arg_index is not None:
            if node.callee_function_name is not None:
                # actual_arg mode: Use location (call location), callee_function_name, and arg_index
                location = node.start_location
                callee_function_name = node.callee_function_name
                arg_index = str(node.arg_index)
                paths = FunctionCFGAnalyzer.trace_paths_to_exit(
                    location=location,
                    callee_function_name=callee_function_name,
                    arg_index=arg_index
                )
            else:
                # formal_arg mode: Use location (function start location) and arg_index
                # The location should be the function start location
                func_info = analysis_operators.find_function_body(function_name)
                if func_info:
                    start_line = func_info.get("start_line", 0)
                    filename = func_info.get("filename", "")
                    location = f"{filename}:{start_line}"
                    arg_index = str(node.arg_index)
                    paths = FunctionCFGAnalyzer.trace_paths_to_exit(
                        location=location,
                        arg_index=arg_index
                    )
                else:
                    logger.error(f"Could not find function body for {function_name}")
                    paths = []
        else:
            logger.warning(f"No eq_position or arg_index for node {node.node_id}")
            paths = []
        
        return cfg, paths
    
    def _extract_tracked_variable(self, node: FunctionAnalysisNode) -> str:
        """
        Extract the tracked variable name based on analysis mode.
        
        Args:
            node: Analysis node
            
        Returns:
            Variable name string
        """
        if node.analysis_mode == "lvar":
            # lvar mode: Extract from source location
            try:
                code_line = find_code_line(node.start_location)
                if code_line:
                    var_name = extract_lhs_variable(code_line)
                    if var_name:
                        return var_name
            except Exception:
                pass
            return "unknown"
        
        elif node.analysis_mode == "formal_arg":
            # formal_arg mode: Extract parameter name from function signature
            if node.function_name and node.arg_index is not None:
                try:
                    alias_set = analysis_operators.get_alias_set_for_formal_arg(
                        node.function_name, node.arg_index
                    )
                    if alias_set:
                        return alias_set[0].get("name", f"parameter_{node.arg_index}")
                except Exception as e:
                    logger.warning(f"Failed to extract formal arg name: {e}")
            return f"parameter_{node.arg_index}" if node.arg_index is not None else "unknown"
        
        elif node.analysis_mode == "actual_arg":
            # actual_arg mode: Extract actual argument expression from function call
            if node.start_location and node.callee_function_name and node.arg_index is not None:
                try:
                    # Use the same logic as FunctionPathAnalyzer
                    code_line = find_code_line(node.start_location, strip_whitespace=False)
                    if code_line:
                        root = parse_code_line(code_line)
                        if root:
                            code_bytes = bytes(code_line, 'utf8')
                            
                            def find_call_expressions(node):
                                calls = []
                                if node.type == "call_expression":
                                    calls.append(node)
                                for child in node.children:
                                    calls.extend(find_call_expressions(child))
                                return calls
                            
                            call_nodes = find_call_expressions(root)
                            
                            for call_node in call_nodes:
                                function_node = call_node.child_by_field_name("function")
                                if function_node is None:
                                    continue
                                
                                func_name = None
                                if function_node.type == "identifier":
                                    func_name = code_bytes[function_node.start_byte:function_node.end_byte].decode("utf8")
                                else:
                                    for child in function_node.children:
                                        if child.type == "identifier":
                                            func_name = code_bytes[child.start_byte:child.end_byte].decode("utf8")
                                            break
                                
                                if func_name and func_name == node.callee_function_name:
                                    arguments_node = call_node.child_by_field_name("arguments")
                                    if arguments_node:
                                        arguments = []
                                        for child in arguments_node.children:
                                            if child.type == "argument_list":
                                                for arg_child in child.children:
                                                    if arg_child.type != ",":
                                                        arguments.append(arg_child)
                                            elif child.type != ",":
                                                arguments.append(child)
                                        
                                        if node.arg_index >= 0 and node.arg_index < len(arguments):
                                            arg_node = arguments[node.arg_index]
                                            arg_text = code_bytes[arg_node.start_byte:arg_node.end_byte].decode("utf8")
                                            arg_expr = re.sub(r"\s+", " ", arg_text.strip())
                                            ord_str = self._get_ordinal_string(node.arg_index)
                                            return f"{node.callee_function_name} call site's {ord_str} actual argument ({arg_expr})"
                except Exception as e:
                    logger.warning(f"Failed to extract actual arg expression: {e}")
            
            # Fallback
            if node.callee_function_name and node.arg_index is not None:
                ord_str = self._get_ordinal_string(node.arg_index)
                return f"{node.callee_function_name} call site's {ord_str} actual argument"
            return "unknown"
        
        return "unknown"
    
    def _get_ordinal_string(self, index: Optional[int]) -> str:
        """Convert 0-based index to ordinal string (first, second, third, etc.)"""
        if index is None:
            return "unknown"
        
        ordinals = ["first", "second", "third", "fourth", "fifth",
                   "sixth", "seventh", "eighth", "ninth", "tenth"]
        if index < len(ordinals):
            return ordinals[index]
        else:
            return f"{index + 1}-th"
    
    def _build_alias_set(self, node: FunctionAnalysisNode) -> List[Dict[str, Any]]:
        """
        Build alias set for the node.
        
        Supports three modes:
        - lvar mode: Uses location and eq_position
        - formal_arg mode: Uses function_name and arg_index
        - actual_arg mode: Uses location, callee_function_name, and arg_index
        
        Args:
            node: Analysis node
            
        Returns:
            List of alias entries
        """
        if node.eq_position is not None:
            # lvar mode: Use get_alias_set
            alias_set = analysis_operators.get_alias_set(
                node.start_location,
                node.eq_position
            )
            return alias_set
        elif node.arg_index is not None:
            if node.callee_function_name is not None:
                # actual_arg mode: Use get_alias_set_for_actual_arg
                alias_set = analysis_operators.get_alias_set_for_actual_arg(
                    node.start_location,
                    node.callee_function_name,
                    node.arg_index
                )
                return alias_set
            else:
                # formal_arg mode: Use get_alias_set_for_formal_arg
                alias_set = analysis_operators.get_alias_set_for_formal_arg(
                    node.function_name,
                    node.arg_index
                )
                return alias_set
        else:
            logger.warning(f"No eq_position or arg_index for node {node.node_id}")
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
        Run path analysis using FunctionPathAnalyzer.
        
        Args:
            node: Analysis node
            
        Returns:
            List of path analysis results
        """
        if not node.paths:
            return []
        
        try:
            # Create FunctionPathAnalyzer instance
            analyzer = FunctionPathAnalyzer(
                paths=node.paths,
                analysis_mode=node.analysis_mode,
                tracked_variable=node.tracked_variable or "unknown",
                function_name=node.function_name,
                start_location=node.start_location,
                alias_set=node.alias_set,
                previous_analysis_paths=node.previous_analysis_paths,
                client=self.client,
                model_name=self.model_name,
                eq_position=node.eq_position,
                arg_index=node.arg_index,
                callee_function_name=node.callee_function_name
            )
            
            # Run analysis
            return analyzer.analyze()
            
        except Exception as e:
            logger.exception(f"Error running path analysis for {node.function_name}: {e}")
            return []
    
    def _output_analysis_results(self):
        """
        Output analysis results, especially key_operation locations for ReturnedAsPointerParameter.
        This method prints a summary of all analysis nodes and their path classifications.
        """
        print("=" * 80)
        print("Cross-Function Analysis Results Summary")
        print("=" * 80)
        logger.info("=" * 80)
        logger.info("Cross-Function Analysis Results Summary")
        logger.info("=" * 80)
        
        for node in self.all_nodes:
            print(f"\n[Node {node.node_id}]")
            print(f"  Function: {node.function_name}")
            print(f"  Start Location: {node.start_location}")
            print(f"  Analysis Status: {node.analysis_status}")
            logger.info(f"\n[Node {node.node_id}]")
            logger.info(f"  Function: {node.function_name}")
            logger.info(f"  Start Location: {node.start_location}")
            logger.info(f"  Analysis Status: {node.analysis_status}")
            
            if node.path_analysis_results:
                print(f"  Path Analysis Results ({len(node.path_analysis_results)} path(s)):")
                logger.info(f"  Path Analysis Results ({len(node.path_analysis_results)} path(s)):")
                for idx, result in enumerate(node.path_analysis_results, 1):
                    classification = result.get("classification")
                    path_id = result.get("path_id")
                    key_operation = result.get("key_operation")
                    reason = result.get("reason")
                    
                    print(f"    Path {path_id} (Result #{idx}):")
                    print(f"      Classification: {classification}")
                    logger.info(f"    Path {path_id} (Result #{idx}):")
                    logger.info(f"      Classification: {classification}")
                    if reason:
                        print(f"      Reason: {reason}")
                        logger.info(f"      Reason: {reason}")
                    
                    # Special handling for ReturnedAsPointerParameter
                    if classification == "ReturnedAsPointerParameter":
                        if key_operation:
                            source_location = key_operation.get("source_location", "N/A")
                            code_line = key_operation.get("code_line", "N/A")
                            print(f"      [ReturnedAsPointerParameter] Key Operation:")
                            print(f"        Location: {source_location}")
                            print(f"        Code Line: {code_line}")
                            logger.info(f"      [ReturnedAsPointerParameter] Key Operation:")
                            logger.info(f"        Location: {source_location}")
                            logger.info(f"        Code Line: {code_line}")
                            
                            # Extract LHS variable if possible
                            if code_line and code_line != "N/A":
                                lhs_var = extract_lhs_variable(code_line)
                                if lhs_var:
                                    print(f"        LHS Variable: {lhs_var}")
                                    logger.info(f"        LHS Variable: {lhs_var}")
                            
                            # Show next functions that will be analyzed
                            if node.children:
                                print(f"      Next Functions to Analyze ({len(node.children)}):")
                                logger.info(f"      Next Functions to Analyze ({len(node.children)}):")
                                for child_idx, child in enumerate(node.children, 1):
                                    print(f"        {child_idx}. {child.function_name} at {child.start_location}")
                                    logger.info(f"        {child_idx}. {child.function_name} at {child.start_location}")
                        else:
                            print(f"      [ReturnedAsPointerParameter] No key_operation found!")
                            logger.warning(f"      [ReturnedAsPointerParameter] No key_operation found!")
                    
                    # Output key_operation for other classifications that have it
                    elif key_operation and classification in ["HandledByCallee", "Deallocated", "ReturnedAsReturnValue"]:
                        source_location = key_operation.get("source_location", "N/A")
                        code_line = key_operation.get("code_line", "N/A")
                        callee_function_name = key_operation.get("callee_function_name", "N/A")
                        print(f"      Key Operation:")
                        print(f"        Location: {source_location}")
                        print(f"        Code Line: {code_line}")
                        logger.info(f"      Key Operation:")
                        logger.info(f"        Location: {source_location}")
                        logger.info(f"        Code Line: {code_line}")
                        if callee_function_name != "N/A":
                            print(f"        Callee Function: {callee_function_name}")
                            logger.info(f"        Callee Function: {callee_function_name}")
            else:
                print(f"  No path analysis results")
                logger.info(f"  No path analysis results")
            
            if node.children:
                print(f"  Child Nodes: {len(node.children)}")
                logger.info(f"  Child Nodes: {len(node.children)}")
        
        print("\n" + "=" * 80)
        print("Analysis Complete")
        print("=" * 80)
        logger.info("\n" + "=" * 80)
        logger.info("Analysis Complete")
        logger.info("=" * 80)
    
    def _output_node_results(self, node: FunctionAnalysisNode):
        """
        Output analysis results for a single node, especially key_operation locations for ReturnedAsPointerParameter.
        This is called immediately after each node is analyzed.
        """
        import sys
        sys.stdout.flush()  # Force flush before output
        
        print(f"\n{'='*80}", flush=True)
        print(f"[Node {node.node_id}] Analysis Complete", flush=True)
        print(f"{'='*80}", flush=True)
        print(f"  Function: {node.function_name}", flush=True)
        print(f"  Start Location: {node.start_location}", flush=True)
        print(f"  Analysis Status: {node.analysis_status}", flush=True)
        logger.info(f"\n[Node {node.node_id}] Analysis Complete")
        logger.info(f"  Function: {node.function_name}")
        logger.info(f"  Start Location: {node.start_location}")
        logger.info(f"  Analysis Status: {node.analysis_status}")
        
        if node.path_analysis_results:
            print(f"  Path Analysis Results ({len(node.path_analysis_results)} path(s)):", flush=True)
            logger.info(f"  Path Analysis Results ({len(node.path_analysis_results)} path(s)):")
            for idx, result in enumerate(node.path_analysis_results, 1):
                classification = result.get("classification")
                path_id = result.get("path_id")
                key_operation = result.get("key_operation")
                reason = result.get("reason")
                
                print(f"    Path {path_id} (Result #{idx}):", flush=True)
                print(f"      Classification: {classification}", flush=True)
                logger.info(f"    Path {path_id} (Result #{idx}):")
                logger.info(f"      Classification: {classification}")
                if reason:
                    print(f"      Reason: {reason[:200]}...", flush=True)  # Truncate long reasons
                    logger.info(f"      Reason: {reason}")
                
                # Special handling for ReturnedAsPointerParameter
                if classification == "ReturnedAsPointerParameter":
                    print(f"      *** [ReturnedAsPointerParameter] DETECTED ***", flush=True)
                    if key_operation:
                        source_location = key_operation.get("source_location", "N/A")
                        code_line = key_operation.get("code_line", "N/A")
                        print(f"      [ReturnedAsPointerParameter] Key Operation:", flush=True)
                        print(f"        Location: {source_location}", flush=True)
                        print(f"        Code Line: {code_line}", flush=True)
                        logger.info(f"      [ReturnedAsPointerParameter] Key Operation:")
                        logger.info(f"        Location: {source_location}")
                        logger.info(f"        Code Line: {code_line}")
                        
                        # Extract LHS variable if possible
                        if code_line and code_line != "N/A":
                            lhs_var = extract_lhs_variable(code_line)
                            if lhs_var:
                                print(f"        LHS Variable: {lhs_var}", flush=True)
                                logger.info(f"        LHS Variable: {lhs_var}")
                        
                        # Show next functions that will be analyzed
                        if node.children:
                            print(f"      Next Functions to Analyze ({len(node.children)}):", flush=True)
                            logger.info(f"      Next Functions to Analyze ({len(node.children)}):")
                            for child_idx, child in enumerate(node.children, 1):
                                print(f"        {child_idx}. {child.function_name} at {child.start_location}", flush=True)
                                logger.info(f"        {child_idx}. {child.function_name} at {child.start_location}")
                    else:
                        print(f"      [ReturnedAsPointerParameter] No key_operation found!", flush=True)
                        logger.warning(f"      [ReturnedAsPointerParameter] No key_operation found!")
                
                # Output key_operation for other classifications that have it
                elif key_operation and classification in ["HandledByCallee", "Deallocated", "ReturnedAsReturnValue"]:
                    source_location = key_operation.get("source_location", "N/A")
                    code_line = key_operation.get("code_line", "N/A")
                    callee_function_name = key_operation.get("callee_function_name", "N/A")
                    print(f"      Key Operation:", flush=True)
                    print(f"        Location: {source_location}", flush=True)
                    print(f"        Code Line: {code_line}", flush=True)
                    logger.info(f"      Key Operation:")
                    logger.info(f"        Location: {source_location}")
                    logger.info(f"        Code Line: {code_line}")
                    if callee_function_name != "N/A":
                        print(f"        Callee Function: {callee_function_name}", flush=True)
                        logger.info(f"        Callee Function: {callee_function_name}")
        else:
            print(f"  No path analysis results", flush=True)
            logger.info(f"  No path analysis results")
        
        if node.children:
            print(f"  Child Nodes: {len(node.children)}", flush=True)
            logger.info(f"  Child Nodes: {len(node.children)}")
        print(f"{'='*80}\n", flush=True)
        logger.info(f"{'='*80}\n")


class FunctionPathAnalyzer:
    """
    独立的路径分析器，用于分析函数路径并分类内存状态。
    完全独立于 FunctionPathBuilderAgent，接受新的路径数据格式。
    """
    
    # Core SVFG node types we care about
    _CORE_SVFG_TYPES = {
        "StoreSVFGNode": ["StoreSVFGNode", "Store"],
        "ActualParmVFGNode": ["ActualParmVFGNode", "ActualParm"],
        "ActualINSVFGNode": ["ActualINSVFGNode", "ActualIN"],
        "GepVFGNode": ["GepVFGNode", "Gep"]
    }
    
    def __init__(self,
                 paths: List[Dict[str, Any]],
                 analysis_mode: str,  # "lvar", "formal_arg", "actual_arg"
                 tracked_variable: str,
                 function_name: str,
                 start_location: str,
                 alias_set: List[Dict[str, Any]],
                 previous_analysis_paths: List[Dict[str, Any]],
                 client=None,
                 model_name=None,
                 eq_position: Optional[int] = None,
                 arg_index: Optional[int] = None,
                 callee_function_name: Optional[str] = None):
        """
        初始化 FunctionPathAnalyzer。
        
        Args:
            paths: 路径数据列表（从 trace_paths_to_exit 返回的格式）
            analysis_mode: 分析模式 ("lvar", "formal_arg", "actual_arg")
            tracked_variable: 被追踪的变量名
            function_name: 函数名
            start_location: 起始位置
            alias_set: 别名集合
            previous_analysis_paths: 前序分析路径
            client: LLM客户端
            model_name: 模型名称
            eq_position: 等式位置（lvar模式）
            arg_index: 参数索引（formal_arg/actual_arg模式）
            callee_function_name: 被调用函数名（actual_arg模式）
        """
        self.paths = paths
        self.analysis_mode = analysis_mode
        self.tracked_variable = tracked_variable
        self.function_name = function_name
        self.start_location = start_location
        self.alias_set = alias_set
        self.previous_analysis_paths = previous_analysis_paths or []
        self.client = client
        self.model_name = model_name
        self.eq_position = eq_position
        self.arg_index = arg_index
        self.callee_function_name = callee_function_name
        
        # 路径数据（用于存储分类结果）
        self.path_data: List[Dict[str, Any]] = []
        
        # 加载SVFG节点（基于模式）
        self.svfg_nodes: List[Dict[str, Any]] = []
        try:
            if self.analysis_mode == "lvar" and eq_position is not None:
                self.svfg_nodes = analysis_operators.find_lvalue_key_svfgnode(
                    start_location, str(eq_position)
                )
            elif self.analysis_mode == "formal_arg" and arg_index is not None:
                self.svfg_nodes = analysis_operators.find_formal_arg_key_svfgnode(
                    function_name, str(arg_index)
                )
            elif self.analysis_mode == "actual_arg" and arg_index is not None and callee_function_name:
                self.svfg_nodes = analysis_operators.find_actual_arg_key_svfgnode(
                    start_location, callee_function_name, str(arg_index)
                )
            logger.info(f"[FunctionPathAnalyzer] Loaded {len(self.svfg_nodes)} SVFG nodes")
        except Exception as e:
            logger.warning(f"[FunctionPathAnalyzer] Failed to fetch SVFG nodes: {e}")
            self.svfg_nodes = []
        
        # 准备路径数据
        self._prepare_path_data()
        
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
    
    def _prepare_path_data(self):
        """准备路径数据，将新格式转换为内部格式。"""
        self.path_data = []
        for idx, path_entry in enumerate(self.paths, start=1):
            # 规范化路径节点
            steps = path_entry.get("steps", [])
            normalized_nodes = self._normalize_path_nodes(steps)
            
            path_entry_data = {
                "path_id": str(idx),
                "path_classification": None,
                "key_operation": None,
                "reason": None,
                "path_node_list": normalized_nodes,
                "original_path": path_entry  # 保存原始路径数据
            }
            self.path_data.append(path_entry_data)
    
    def _normalize_path_nodes(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        规范化路径节点格式，将新的 steps 格式转换为用于 prompt 构建的节点列表格式。
        
        Args:
            steps: 路径步骤列表（包含 node, edge, svfg_nodes, is_key_location）
            
        Returns:
            规范化后的节点列表
        """
        normalized_nodes = []
        
        for step in steps:
            node_info = step.get("node", {})
            edge_info = step.get("edge")
            svfg_nodes = step.get("svfg_nodes", [])
            
            # 提取节点信息
            node_type = node_info.get("type", "unknown")
            location = node_info.get("location", "")
            condition_value = None
            expression = None
            
            # 处理分支节点
            if node_type == "branch" and edge_info:
                edge_type = edge_info.get("type", "")
                if edge_type == "true_branch":
                    condition_value = "true"
                elif edge_type == "false_branch":
                    condition_value = "false"
                elif edge_type == "switch_case":
                    condition_value = edge_info.get("condition", "")
                
                # 从 conditions 中提取表达式
                # 注意：表达式信息应该在路径的 conditions 字段中
                expression = node_info.get("condition", "")
            
            # 构建 node_desc（用于分支表达式提取）
            node_desc = ""
            if location:
                try:
                    file_part, line_part = location.split(":")
                    line_num = int(line_part)
                    # 尝试从代码行中提取列号
                    code_line = find_code_line(location, strip_whitespace=False)
                    if code_line and expression:
                        cond_idx = code_line.find(expression)
                        if cond_idx >= 0:
                            col_num = cond_idx + 1  # 1-based
                        else:
                            col_num = 1
                    else:
                        col_num = 1
                    node_desc = f'{{"ln": {line_num}, "cl": {col_num}, "fl": "{file_part}"}}'
                except Exception:
                    try:
                        file_part, line_part = location.split(":")
                        node_desc = f'{{"ln": {line_part}, "cl": 1, "fl": "{file_part}"}}'
                    except:
                        pass
            
            normalized_node = {
                "node": node_type,
                "location": location,
                "condition_value": condition_value,
                "expression": expression,
                "node_desc": node_desc
            }
            
            # 保留其他字段
            if "statements" in node_info:
                normalized_node["statements"] = node_info["statements"]
            if "start_line" in node_info:
                normalized_node["start_line"] = node_info["start_line"]
            if "end_line" in node_info:
                normalized_node["end_line"] = node_info["end_line"]
            
            normalized_nodes.append(normalized_node)
        
        return normalized_nodes
    
    def _match_svfg_to_paths(self, path_node_list: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        从路径的 steps 中提取 SVFG 节点信息。
        注意：新的路径数据格式已经包含 SVFG 绑定信息，但我们需要构建 location 到 SVFG 的映射。
        
        Args:
            path_node_list: 路径节点列表
            
        Returns:
            位置到 SVFG 节点的映射字典
        """
        location_to_svfg = {}
        
        # 从原始路径数据中提取 SVFG 信息
        for path_entry_data in self.path_data:
            original_path = path_entry_data.get("original_path", {})
            steps = original_path.get("steps", [])
            
            for step in steps:
                node_info = step.get("node", {})
                location = node_info.get("location", "")
                svfg_nodes = step.get("svfg_nodes", [])
                
                if location and svfg_nodes:
                    if location not in location_to_svfg:
                        location_to_svfg[location] = []
                    location_to_svfg[location].extend(svfg_nodes)
        
        # 也尝试从 self.svfg_nodes 中匹配（作为补充）
        path_locations = {node.get("location", "") for node in path_node_list if node.get("location")}
        
        for svfg_node in self.svfg_nodes:
            svfg_location = svfg_node.get("location", "")
            if not svfg_location:
                continue
            
            # 直接匹配
            if svfg_location in path_locations:
                if svfg_location not in location_to_svfg:
                    location_to_svfg[svfg_location] = []
                location_to_svfg[svfg_location].append(svfg_node)
            else:
                # 尝试按 file:line 匹配（忽略列）
                try:
                    svfg_file_line = ":".join(svfg_location.split(":")[:2]) if ":" in svfg_location else ""
                    for path_loc in path_locations:
                        path_file_line = ":".join(path_loc.split(":")[:2]) if ":" in path_loc else ""
                        if svfg_file_line == path_file_line and svfg_file_line:
                            if path_loc not in location_to_svfg:
                                location_to_svfg[path_loc] = []
                            location_to_svfg[path_loc].append(svfg_node)
                            break
                except Exception:
                    pass
        
        return location_to_svfg
    
    def _analyze_path_features(self, path_node_list: List[Dict[str, Any]], 
                               location_to_svfg: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        分析路径中的内存操作特征（store, actualparam, actualin, gep等）。
        
        Args:
            path_node_list: 路径节点列表
            location_to_svfg: 位置到 SVFG 节点的映射
            
        Returns:
            包含分析结果的字典
        """
        has_store = False
        has_actualparam = False
        has_actualin = False
        has_gep = False
        svfg_details = []
        
        for node in path_node_list:
            location = node.get("location", "")
            node_type = node.get("node", "")
            
            # 检查是否有匹配的 SVFG 节点
            matching_svfgs = location_to_svfg.get(location, [])
            
            for svfg_node in matching_svfgs:
                svfg_node_type = svfg_node.get("node_type", "")
                
                # 分析 SVFG 节点类型
                core_type = self._is_core_svfg_type(svfg_node_type)
                if core_type:
                    if core_type == "StoreSVFGNode":
                        has_store = True
                    elif core_type == "ActualParmVFGNode":
                        has_actualparam = True
                    elif core_type == "ActualINSVFGNode":
                        has_actualin = True
                    elif core_type == "GepVFGNode":
                        has_gep = True
                    
                    svfg_details.append({
                        "location": location,
                        "type": core_type,
                        "description": svfg_node.get("node_desc", "")
                    })
            
            # 也检查路径节点类型作为后备
            if not matching_svfgs:
                if node_type == "store" or "Store" in node_type:
                    has_store = True
                elif "ActualParm" in node_type or "actualparam" in node_type.lower():
                    has_actualparam = True
                elif "ActualIN" in node_type or "actualin" in node_type.lower():
                    has_actualin = True
                elif "GEP" in node_type or "gep" in node_type.lower():
                    has_gep = True
        
        return {
            "has_store": has_store,
            "has_actualparam": has_actualparam,
            "has_actualin": has_actualin,
            "has_gep": has_gep,
            "svfg_details": svfg_details
        }
    
    def _is_core_svfg_type(self, svfg_node_type: str) -> Optional[str]:
        """
        判断 SVFG 节点是否为核心类型。
        
        Args:
            svfg_node_type: SVFG 节点类型字符串
            
        Returns:
            核心类型名称（如果匹配），否则 None
        """
        for core_type, patterns in self._CORE_SVFG_TYPES.items():
            for pattern in patterns:
                if pattern in svfg_node_type:
                    return core_type
        return None
    
    def _get_svfg_description(self, svfg_node: Dict[str, Any], code_line: str) -> str:
        """
        根据 SVFG 节点类型生成描述文本。
        
        Args:
            svfg_node: SVFG 节点字典
            code_line: 源代码行内容
            
        Returns:
            描述字符串
        """
        svfg_type = svfg_node.get("node_type", "")
        node_desc = svfg_node.get("node_desc", "")
        
        if "StoreSVFGNode" in svfg_type or "Store" in svfg_type:
            if "RETMU" in node_desc or "return" in node_desc.lower():
                return " (SVFG: StoreVFGNode - memory stored and may be returned via return value)"
            elif "parameter" in node_desc.lower() or "param" in node_desc.lower():
                return " (SVFG: StoreVFGNode - memory stored into function parameter)"
            else:
                return " (SVFG: StoreVFGNode - memory stored into variable/pointer)"
        elif "ActualParmVFGNode" in svfg_type or "ActualParm" in svfg_type:
            if "free" in code_line.lower() or "dealloc" in code_line.lower():
                return " (SVFG: ActualParmVFGNode - variable passed as argument to deallocation function)"
            else:
                return " (SVFG: ActualParmVFGNode - variable passed as actual parameter to function call)"
        elif "ActualINSVFGNode" in svfg_type or "ActualIN" in svfg_type:
            if "free" in code_line.lower() or "dealloc" in code_line.lower():
                return " (SVFG: ActualINSVFGNode - variable passed as input argument to deallocation function)"
            else:
                return " (SVFG: ActualINSVFGNode - variable passed as input argument to function call)"
        elif "GepVFGNode" in svfg_type or "Gep" in svfg_type:
            return " (SVFG: GepVFGNode - getelementptr operation, accessing structure member or array element)"
        elif "AddrVFGNode" in svfg_type or "Addr" in svfg_type:
            return " (SVFG: AddrVFGNode - address of variable is taken)"
        elif "FormalINSVFGNode" in svfg_type or "FormalIN" in svfg_type:
            return " (SVFG: FormalINSVFGNode - variable received as formal input parameter)"
        else:
            return f" (SVFG: {svfg_type})"
    
    def _extract_variable_name(self) -> str:
        """
        根据分析模式提取变量名。
        
        Returns:
            变量名字符串
        """
        if self.analysis_mode == "lvar":
            # lvar 模式：从起始位置提取
            try:
                code_line = find_code_line(self.start_location)
                if code_line:
                    var_name = extract_lhs_variable(code_line)
                    if var_name:
                        return var_name
            except Exception:
                pass
            return self.tracked_variable or "unknown"
        elif self.analysis_mode == "formal_arg":
            # formal_arg 模式：从函数签名提取参数名
            if self.function_name and self.arg_index is not None:
                try:
                    func_info = analysis_operators.find_function_body(self.function_name)
                    if func_info and not func_info.get("error"):
                        alias_set = analysis_operators.get_alias_set_for_formal_arg(
                            self.function_name, self.arg_index
                        )
                        if alias_set:
                            return alias_set[0].get("name", f"parameter_{self.arg_index}")
                except Exception as e:
                    logger.warning(f"Failed to extract formal arg name: {e}")
            return self.tracked_variable or (f"parameter_{self.arg_index}" if self.arg_index is not None else "unknown")
        elif self.analysis_mode == "actual_arg":
            # actual_arg 模式：从函数调用提取实际参数表达式
            if self.start_location and self.callee_function_name and self.arg_index is not None:
                try:
                    arg_expr = self._extract_actual_argument_expression(
                        self.start_location, self.callee_function_name, self.arg_index
                    )
                    if arg_expr:
                        arg_expr = re.sub(r"\s+", " ", arg_expr.strip())
                        ord_str = self._get_ordinal_string(self.arg_index)
                        code_line = find_code_line(self.start_location) or ""
                        return f"{self.callee_function_name} call site's {ord_str} actual argument ({arg_expr})"
                    else:
                        ord_str = self._get_ordinal_string(self.arg_index)
                        return f"{self.callee_function_name} call site's {ord_str} actual argument"
                except Exception as e:
                    logger.warning(f"Failed to extract actual arg expression: {e}")
            if self.callee_function_name and self.arg_index is not None:
                ord_str = self._get_ordinal_string(self.arg_index)
                return f"{self.callee_function_name} call site's {ord_str} actual argument"
            return self.tracked_variable or "unknown"
        
        return self.tracked_variable or "unknown"
    
    def _should_filter_node_description(self, node_type: str, location: str,
                                       is_start_node: bool = False,
                                       core_svfg_type: Optional[str] = None,
                                       matching_svfgs: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        判断节点描述是否应该被过滤（不显示详细信息）。
        
        Args:
            node_type: 节点类型
            location: 位置字符串
            is_start_node: 是否为起始节点
            core_svfg_type: 核心 SVFG 类型
            matching_svfgs: 匹配的 SVFG 节点列表
            
        Returns:
            True 如果应该过滤，否则 False
        """
        # 检查 SVFG 类型是否表示 actualparam/actualin
        is_svfg_actual_param = (core_svfg_type in ("ActualParmVFGNode", "ActualINSVFGNode"))
        is_actual_param_type = ("ActualParm" in node_type or "actualparam" in node_type.lower() or
                               "ActualIN" in node_type or "actualin" in node_type.lower())
        should_check_filter = is_actual_param_type or is_svfg_actual_param
        
        # 检查位置是否匹配 key_svfg 节点
        key_locs = {svfg.get("location", "") for svfg in self.svfg_nodes}
        if location in key_locs:
            if should_check_filter or is_start_node:
                return True
        
        # 检查前序路径条件
        if not should_check_filter:
            return False
        
        if self.previous_analysis_paths:
            last_path = self.previous_analysis_paths[-1]
            last_classification = last_path.get("classification", "")
            
            if last_classification == "ReturnedAsPointerParameter":
                if self.analysis_mode == "actual_arg" and self.callee_function_name:
                    prev_function_name = last_path.get("function_name", "")
                    if self.callee_function_name == prev_function_name:
                        if location == self.start_location or self._locations_match(location, self.start_location):
                            return True
        
        return False
    
    def _locations_match(self, loc1: str, loc2: str) -> bool:
        """检查两个位置字符串是否匹配（按 file:line，忽略列）。"""
        if not loc1 or not loc2:
            return False
        if loc1 == loc2:
            return True
        
        try:
            loc1_parts = loc1.split(":")
            loc2_parts = loc2.split(":")
            if len(loc1_parts) >= 2 and len(loc2_parts) >= 2:
                return loc1_parts[0] == loc2_parts[0] and loc1_parts[1] == loc2_parts[1]
        except Exception:
            pass
        
        return False
    
    def _format_previous_analysis_paths(self) -> str:
        """
        格式化前序分析路径为 prompt 字符串。
        
        Returns:
            格式化的 prompt 字符串
        """
        if not self.previous_analysis_paths:
            return ""
        
        prompt_lines = ["Here is the analysis path leading to the current function:"]
        prompt_lines.append("The following conditions should be satisfied:")
        
        for idx, path_entry in enumerate(self.previous_analysis_paths):
            function_name = path_entry.get("function_name", "unknown function")
            start_location = path_entry.get("start_location", "")
            classification = path_entry.get("classification", "unknown state")
            key_operation = path_entry.get("key_operation")
            reason = path_entry.get("reason", "")
            conditions = path_entry.get("conditions", [])
            
            start_line_code = self._safe_find_code_line(start_location)
            
            path_desc = f"- In function {function_name} at {start_location}"
            if start_line_code:
                path_desc += f" : {start_line_code}"
            path_desc += f", the memory flow was classified as {classification}"
            
            if key_operation:
                key_op_location = key_operation.get("source_location", "")
                key_op_code = self._safe_find_code_line(key_op_location)
                if key_op_location:
                    path_desc += f" with key operation at {key_op_location}"
                    if key_op_code:
                        path_desc += f" : {key_op_code}"
            
            if reason:
                reason_short = reason[:200] + "..." if len(reason) > 200 else reason
                path_desc += f" (reason: {reason_short})"
            
            prompt_lines.append(path_desc)
            
            # 添加分支条件信息
            if conditions:
                prompt_lines.append(f"  The following condition branches were taken in function {function_name}:")
                for cond_idx, cond in enumerate(conditions, 1):
                    cond_location = cond.get("location", "")
                    cond_expression = cond.get("expression", "")
                    cond_value = cond.get("condition_value", "")
                    cond_code = cond.get("code_line", "")
                    
                    if cond_expression:
                        cond_desc = f"    {cond_idx}. At {cond_location}"
                        if cond_code:
                            cond_desc += f" : {cond_code}"
                        cond_desc += f", condition \"{cond_expression}\""
                        if cond_value:
                            cond_desc += f" evaluated to {cond_value}"
                        else:
                            cond_desc += " was evaluated"
                        prompt_lines.append(cond_desc)
                    elif cond_location:
                        cond_desc = f"    {cond_idx}. Branch at {cond_location}"
                        if cond_code:
                            cond_desc += f" : {cond_code}"
                        if cond_value:
                            cond_desc += f" (taken: {cond_value})"
                        prompt_lines.append(cond_desc)
        
        prompt_lines.append("")
        prompt_lines.append("IMPORTANT: These condition branches from previous functions constrain the feasible execution paths in the current function. Any path in the current function that contradicts these conditions should be classified as Unreachable.")
        prompt_lines.append("Please continue the analysis from this path context, ensuring consistency with the above conditions.")
        return "\n".join(prompt_lines) + "\n\n"
    
    def _safe_find_code_line(self, location: str) -> str:
        """安全地查找代码行。"""
        if not location:
            return ""
        try:
            return find_code_line(location)
        except Exception:
            return ""
    
    def _get_ordinal_string(self, index: Optional[int]) -> str:
        """将索引转换为序数字符串（first, second, third等）。"""
        if index is None:
            return "unknown"
        
        ordinals = ["first", "second", "third", "fourth", "fifth",
                   "sixth", "seventh", "eighth", "ninth", "tenth"]
        if index < len(ordinals):
            return ordinals[index]
        else:
            return f"{index + 1}-th"
    
    def _extract_actual_argument_expression(self, location: str, callee_function_name: str, arg_index: int) -> Optional[str]:
        """
        从函数调用中提取实际参数表达式。
        
        Args:
            location: 调用位置的源代码位置
            callee_function_name: 被调用函数名
            arg_index: 参数索引（0-based）
            
        Returns:
            参数表达式文本（如果找到），否则 None
        """
        code_line = find_code_line(location, strip_whitespace=False)
        if not code_line:
            return None
        
        root = parse_code_line(code_line)
        if root is None:
            return None
        
        code_bytes = bytes(code_line, 'utf8')
        
        def find_call_expressions(node):
            calls = []
            if node.type == "call_expression":
                calls.append(node)
            for child in node.children:
                calls.extend(find_call_expressions(child))
            return calls
        
        call_nodes = find_call_expressions(root)
        
        target_call = None
        for call_node in call_nodes:
            function_node = call_node.child_by_field_name("function")
            if function_node is None:
                continue
            
            func_name = None
            if function_node.type == "identifier":
                func_name = code_bytes[function_node.start_byte:function_node.end_byte].decode("utf8")
            else:
                for child in function_node.children:
                    if child.type == "identifier":
                        func_name = code_bytes[child.start_byte:child.end_byte].decode("utf8")
                        break
            
            if func_name and func_name == callee_function_name:
                target_call = call_node
                break
        
        if target_call is None:
            return None
        
        arguments_node = target_call.child_by_field_name("arguments")
        if arguments_node is None:
            return None
        
        arguments = []
        for child in arguments_node.children:
            if child.type == "argument_list":
                for arg_child in child.children:
                    if arg_child.type != ",":
                        arguments.append(arg_child)
            elif child.type != ",":
                arguments.append(child)
        
        if arg_index < 0 or arg_index >= len(arguments):
            return None
        
        arg_node = arguments[arg_index]
        arg_text = code_bytes[arg_node.start_byte:arg_node.end_byte].decode("utf8")
        return re.sub(r"\s+", " ", arg_text.strip())
    
    def build_prompt(self) -> str:
        """
        构建用于路径分类的 prompt。
        
        Returns:
            prompt 字符串
        """
        var_name = self._extract_variable_name()
        path_count = len(self.path_data)
        
        # 获取当前函数信息
        if self.analysis_mode == "formal_arg" and self.function_name:
            current_function_name = self.function_name
            try:
                func_info = analysis_operators.find_function_body(self.function_name)
                if func_info and not func_info.get("error"):
                    start_line = func_info.get("start_line", 0)
                    filename = func_info.get("filename", "")
                    function_location = f"{filename}:{start_line}" if filename else self.start_location
                else:
                    function_location = self.start_location
            except Exception:
                function_location = self.start_location
        else:
            current_function_info = self.find_current_function_Tool(self.start_location)
            current_function_name = current_function_info.get('function_name', 'unknown')
            function_location = self.start_location
        
        # 开始构建 prompt
        prompt_parts = []
        previous_paths_prompt = self._format_previous_analysis_paths()
        if previous_paths_prompt:
            prompt_parts.append(previous_paths_prompt)
        
        # 根据模式构建介绍
        if self.analysis_mode == "actual_arg":
            intro_lines = [
                f"You are tracing the value flow of the {self._get_ordinal_string(self.arg_index)} actual argument at the call site: {self.start_location} : {find_code_line(self.start_location) or ''}",
                f"The variable being traced is: {var_name}"
            ]
            if self.previous_analysis_paths:
                intro_lines.append("This analysis continues from the previous function call, tracing the memory flow after the function returned.")
            intro_lines.append(f"The static analysis engine pruned the control-flow in function {current_function_name} and identified {path_count} candidate paths. Each path is described below.")
            prompt_parts.extend(intro_lines)
        elif self.analysis_mode == "formal_arg":
            prompt_parts.extend([
                f"You are tracing the value flow of the {self._get_ordinal_string(self.arg_index)} formal parameter of function {current_function_name} (starting at {function_location}) to detect potential memory leaks.",
                f"The variable being traced is: {var_name}",
                f"The static analysis engine pruned the control-flow in function {current_function_name} and identified {path_count} candidate paths. Each path is described below."
            ])
        else:
            # lvar 模式
            prompt_parts.extend([
                f"You are tracing the value flow of variable '{var_name}' to detect potential memory leaks. start from the location: {self.start_location} : {find_code_line(self.start_location)}",
                f"The static analysis engine pruned the control-flow in function {current_function_name} and identified {path_count} candidate paths. Each path is described below."
            ])
        
        # 构建路径描述
        for idx, path_entry in enumerate(self.path_data, start=1):
            path_id = path_entry["path_id"]
            path_node_list = path_entry.get("path_node_list", [])
            original_path = path_entry.get("original_path", {})
            conditions = original_path.get("conditions", [])
            
            # 匹配 SVFG 节点到路径
            location_to_svfg = self._match_svfg_to_paths(path_node_list)
            
            # 分析路径特征
            path_analysis = self._analyze_path_features(path_node_list, location_to_svfg)
            has_store = path_analysis["has_store"]
            has_actualparam = path_analysis["has_actualparam"]
            has_actualin = path_analysis["has_actualin"]
            has_gep = path_analysis["has_gep"]
            svfg_details = path_analysis["svfg_details"]
            
            # 创建位置到核心 SVFG 类型的映射
            location_to_core_svfg_type = {}
            for detail in svfg_details:
                loc = detail["location"]
                if loc not in location_to_core_svfg_type:
                    location_to_core_svfg_type[loc] = detail["type"]
            
            path_observations = []
            path_details = []
            
            for node in path_node_list:
                node_type = node.get("node", "")
                location = node.get("location", "")
                condition_value = node.get("condition_value")
                expression = node.get("expression")
                
                code_line = find_code_line(location) if location else ""
                if not code_line:
                    code_line = location
                
                # 获取 SVFG 信息
                matching_svfgs = location_to_svfg.get(location, [])
                core_svfg_type = location_to_core_svfg_type.get(location)
                
                # 获取 SVFG 描述
                svfg_info = ""
                if matching_svfgs and core_svfg_type:
                    for svfg in matching_svfgs:
                        if self._is_core_svfg_type(svfg.get("node_type", "")) == core_svfg_type:
                            svfg_info = self._get_svfg_description(svfg, code_line)
                            break
                elif matching_svfgs:
                    svfg_info = self._get_svfg_description(matching_svfgs[0], code_line)
                
                # 检查是否应该过滤节点描述
                should_filter = self._should_filter_node_description(
                    node_type, location,
                    is_start_node=(node_type == "start"),
                    core_svfg_type=core_svfg_type,
                    matching_svfgs=matching_svfgs
                )
                
                if node_type == "start":
                    if self.analysis_mode == "actual_arg" or self.analysis_mode == "formal_arg":
                        path_details.append(f"  - Variable entry at {location} : {code_line}")
                    else:
                        path_details.append(f"  - Allocation start at {location} : {code_line}")
                elif node_type == "branch":
                    cond_str = condition_value if condition_value not in (None, "") else "unknown"
                    if expression:
                        path_details.append(f"  - Node type branch {location} : condition \"{expression}\" evaluated to {cond_str}")
                    else:
                        path_details.append(f"  - Node type branch {location} : {code_line} (condition evaluated to {cond_str})")
                elif node_type == "store" or "Store" in node_type:
                    base_desc = f"  - Node type {node_type} {location} : {code_line} (memory likely stored into parameters/return value)"
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif "ActualParm" in node_type or "actualparam" in node_type.lower():
                    if "free" in code_line.lower() or "dealloc" in code_line.lower():
                        base_desc = f"  - Node type {node_type} {location} : {code_line} (variable used as argument of a deallocation function)"
                    else:
                        base_desc = f"  - Node type {node_type} {location} : {code_line}"
                        if not should_filter:
                            base_desc += " (SVFG: ActualParmVFGNode - variable passed as actual parameter to function call)"
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif "ActualIN" in node_type or "actualin" in node_type.lower():
                    base_desc = f"  - Node type {node_type} {location} : {code_line}"
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif node_type == "return":
                    path_details.append(f"  - return statement {location} : {code_line}")
                else:
                    base_desc = f"  - Node type {node_type} {location} : {code_line}"
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
            
            # 构建路径观察描述
            if has_store:
                path_observations.append("store operations detected; ownership may be passed to parameters or return values")
            if has_actualparam:
                path_observations.append("variable is used as a call argument; ownership may transfer to the callee or be freed there")
            if has_actualin:
                path_observations.append("variable passed as input argument; may be used by callee function")
            if has_gep:
                path_observations.append("pointer arithmetic/field access detected; memory may be accessed through structure or array")
            
            if not (has_store or has_actualparam or has_actualin):
                path_observations.append("no memory transfer detected; potential leak at return")
            
            observations_str = " ".join(path_observations) if path_observations else "no noteworthy memory events"
            
            prompt_parts.append(f"{idx}. path_id: {idx}: {observations_str}")
            prompt_parts.extend(path_details)
        
        prompt_parts.extend([
            "",
            " Your task is to classify each path into one of the following memory states:",
            "- HandledByCallee: memory will be handled by a callee function.",
            "- Deallocated: memory is explicitly freed (e.g., free or custom free).",
            "- ReturnedAsReturnValue: memory is returned via the function's return value.",
            "- ReturnedAsPointerParameter: memory is returned through a pointer parameter.",
            "- Leak: memory is leaked at this return location.",
            "- NullPointer: the pointer remains NULL due to allocation failures.",
            "- Unreachable: the path is infeasible due to control-flow constraints.",
            "",
            "For each path, you must first check if the path is feasible. If the path is not feasible, you should classify it as Unreachable directly.",
        ])
        
        return "\n".join(prompt_parts)
    
    # 工具方法（用于LLM交互）
    def dump_source_snippet_Tool(self, file_name, start_line, end_line):
        return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
    def dump_source_line_Tool(self, file_name, line_number):
        return analysis_operators.dump_source_line(file_name, line_number)
    
    def find_current_function_Tool(self, source_location):
        return analysis_operators.find_current_function(source_location)
    
    def find_function_body_Tool(self, function_name):
        return analysis_operators.find_function_body(function_name)
    
    def find_callers_Tool(self, function_name):
        return analysis_operators.find_callers(function_name)
    
    def read_ctag_symbol_Tool(self, symbol_name):
        return analysis_operators.read_ctag_symbol(symbol_name)
    
    def complete_path_Tool(self, path_id: str, classification: str, reason: str,
                          key_operation_source_location: Optional[str] = None,
                          key_operation_code_line: Optional[str] = None,
                          callee_function_name: Optional[str] = None) -> Dict[str, Any]:
        """
        完成路径分类。
        
        Args:
            path_id: 路径标识符
            classification: 路径分类
            reason: 分类原因
            key_operation_source_location: 关键操作的源代码位置
            key_operation_code_line: 关键操作的代码行
            callee_function_name: 被调用函数名
            
        Returns:
            包含成功信息或错误信息的字典
        """
        path_id = str(path_id)
        
        # 查找路径
        path_entry = next((p for p in self.path_data if p["path_id"] == path_id), None)
        if path_entry is None:
            return {"error": f"path_id {path_id} not found"}
        
        # 检查路径是否已完成
        if path_entry["path_classification"] is not None:
            return {"error": f"path_id {path_id} is already completed with classification {path_entry['path_classification']}"}
        
        # 验证分类类型
        valid_classifications = [
            "HandledByCallee", "Deallocated", "ReturnedAsReturnValue",
            "ReturnedAsPointerParameter", "Leak", "NullPointer", "Unreachable"
        ]
        if classification not in valid_classifications:
            return {"error": f"unknown classification: {classification}. Valid types: {valid_classifications}"}
        
        # 对于需要key_operation的分类，进行验证
        requires_key_operation = classification in [
            "HandledByCallee", "Deallocated", "ReturnedAsReturnValue", "ReturnedAsPointerParameter"
        ]
        requires_function_name = classification in ["HandledByCallee", "Deallocated"]
        
        if requires_key_operation:
            if not key_operation_source_location:
                return {"error": f"key_operation_source_location is required for classification {classification}"}
            if not key_operation_code_line:
                return {"error": f"key_operation_code_line is required for classification {classification}"}
            
            if requires_function_name:
                if not callee_function_name:
                    return {"error": f"callee_function_name is required for classification {classification}"}
                if callee_function_name not in key_operation_code_line:
                    return {
                        "error": f"callee_function_name '{callee_function_name}' must appear in key_operation_code_line: '{key_operation_code_line}'"
                    }
            
            if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', key_operation_source_location):
                return {"error": f"invalid key_operation_source_location format: {key_operation_source_location}"}
            
            # 验证source_location必须匹配路径中某个非branch节点
            path_node_list = path_entry.get("path_node_list", [])
            matching_node = None
            for node in path_node_list:
                node_location = node.get("location")
                node_type = node.get("node", "")
                if node_location == key_operation_source_location and node_type != "branch":
                    matching_node = node
                    break
            
            if matching_node is None:
                non_branch_locations = [
                    n.get("location") for n in path_node_list
                    if n.get("node") != "branch"
                ]
                return {
                    "error": f"key_operation_source_location {key_operation_source_location} does not match any non-branch node in the path. "
                             f"Available non-branch node locations: {non_branch_locations}"
                }
            
            # 验证并规范化source_location和code_line
            validation_result = analysis_operators.validate_source_location(
                key_operation_source_location, key_operation_code_line
            )
            if "error" in validation_result:
                return {"error": f"source_location validation failed: {validation_result['error']}"}
            
            validated_location = validation_result["source_location"]
            validated_code_line = validation_result.get("code_line", key_operation_code_line)
            
            key_operation_data = {
                "source_location": validated_location,
                "code_line": validated_code_line
            }
            
            if requires_function_name and callee_function_name:
                key_operation_data["callee_function_name"] = callee_function_name
            
            path_entry["key_operation"] = key_operation_data
        else:
            path_entry["key_operation"] = None
        
        # 设置分类和原因
        path_entry["path_classification"] = classification
        path_entry["reason"] = reason
        
        logger.info(
            f"[FunctionPathAnalyzer] complete_path path_id={path_id} "
            f"classification={classification} key_operation={path_entry['key_operation']}"
        )
        
        return {
            "success": True,
            "path_id": path_id,
            "classification": classification,
            "reason": reason,
            "key_operation": path_entry["key_operation"]
        }
    
    def send_message(self, messages, tools=""):
        """发送消息到LLM并返回响应。"""
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        print(
            "[FunctionPathAnalyzer] response content=%s"
            % (response.choices[0].message.content if response.choices[0].message else None)
        )
        print(
            "[FunctionPathAnalyzer] received response has_content=%s tool_calls=%d"
            % (
                bool(response.choices[0].message.content),
                len(response.choices[0].message.tool_calls or []),
            )
        )
        return response.choices[0].message
    
    def handle_agent_tool_call(self, tool_call):
        """处理Agent的工具调用。"""
        function_name = "unknown"
        try:
            function_obj = getattr(tool_call, "function", tool_call)
            function_name = getattr(function_obj, "name", None)
            if not function_name:
                raise ValueError("missing function name in tool call")
            
            raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
            tool_arguments = safe_load_json(raw_arguments)
            
            print("[FunctionPathAnalyzer] tool_call name=%s arguments=%s" % (function_name, raw_arguments))
            
            handler = self.tool_method_map.get(function_name)
            if handler is None:
                return {"error": f"unknown tool function: {function_name}"}
            
            if isinstance(tool_arguments, dict):
                result = handler(**tool_arguments)
            elif isinstance(tool_arguments, list):
                result = handler(*tool_arguments)
            else:
                result = handler(tool_arguments)
            
            print("[FunctionPathAnalyzer] tool_call result=%s" % (result))
            return result
        except Exception as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}
    
    def check_path_completeness(self):
        """检查哪些路径尚未完成。"""
        incomplete_paths = []
        for path_entry in self.path_data:
            if path_entry.get("path_classification") is None:
                incomplete_paths.append(path_entry["path_id"])
        return incomplete_paths
    
    def _get_allowed_tools(self):
        """获取允许使用的工具列表。"""
        from tools import (
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            read_ctag_symbol_desc_free,
            complete_path_desc_function_path_builder
        )
        return [
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            read_ctag_symbol_desc_free,
            complete_path_desc_function_path_builder
        ]
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        主分析方法：分析所有路径并返回分类结果。
        
        Returns:
            分类结果列表
        """
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        # 构建初始 prompt
        prompt = self.build_prompt()
        print("[FunctionPathAnalyzer] user_prompt=\n%s" % prompt)
        
        # 构建系统 prompt
        system_prompt = VALUE_PATH_PROMPT + "\n" + ASSUMPTION_PROMPT
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        allowed_tools = self._get_allowed_tools()
        response = self.send_message(messages, allowed_tools)
        
        if not response.content:
            response.content = ""
        messages.append(response)
        
        # 主循环：继续直到所有路径都被分类
        while True:
            if not response.tool_calls:
                # 检查是否所有路径都已完成
                incomplete_paths = self.check_path_completeness()
                if len(incomplete_paths) == 0:
                    break
                
                # 提示完成剩余路径
                messages.append({
                    "role": "user",
                    "content": (
                        f"The following paths are not yet completed: {incomplete_paths}. "
                        "Please complete these paths by classifying their memory state using the complete_path tool."
                    )
                })
                response = self.send_message(messages, allowed_tools)
                if not response.content:
                    response.content = ""
                messages.append(response)
                continue
            
            # 处理每个工具调用
            for tool_call in response.tool_calls:
                function_response = self.handle_agent_tool_call(tool_call)
                if not isinstance(function_response, str):
                    import json
                    function_response = json.dumps(function_response, ensure_ascii=False)
                print("[FunctionPathAnalyzer] function_response=%s" % (function_response))
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "content": function_response
                })
            
            # 获取下一个响应
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            messages.append(response)
        
        # 提取结果
        results = []
        for path_entry in self.path_data:
            result = {
                "path_id": path_entry.get("path_id"),
                "classification": path_entry.get("path_classification"),
                "reason": path_entry.get("reason"),
                "key_operation": path_entry.get("key_operation")
            }
            results.append(result)
        
        return results


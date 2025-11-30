import json
import logging
import re
from typing import List, Dict, Any, Optional
from openai import OpenAI
import analysis_operators
from utils import find_code_line

logger = logging.getLogger(__name__)

class PathBranchExtractorAgent:
    """
    PathBranchExtractor Agent
    
    Extracts and deconstructs branch conditions from a path to facilitate Z3 verification.
    Collaborates with PathZ3CheckerAgent by providing enriched path data with explicit constraints.
    """
    
    def __init__(self, path_data: List[Dict[str, Any]], client: Optional[OpenAI] = None, model_name: str = "gpt-4"):
        """
        Initialize the PathBranchExtractorAgent.
        
        Args:
            path_data: List of path data dictionaries.
            client: OpenAI client instance.
            model_name: Name of the model to use.
        """
        self.path_data = path_data
        self.client = client
        self.model_name = model_name
        self.current_path_id = None
        self.execution_trace = []
        
        # Tool method mapping
        self.tool_method_map = {
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "read_ctag_symbol": self.read_ctag_symbol_Tool,
            "add_condition_constraint": self.add_condition_constraint_Tool,
            "deconstruct_condition_constraint": self.deconstruct_condition_constraint_Tool,
            "add_relevant_operation": self.add_relevant_operation_Tool,
        }

    def dump_source_snippet_Tool(self, file_name, start_line, end_line):
        """Get source code snippet."""
        return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
    def dump_source_line_Tool(self, file_name, line_number):
        """Get single line of source code."""
        return analysis_operators.dump_source_line(file_name, line_number)

    def read_ctag_symbol_Tool(self, symbol_name):
        """Look up symbol occurrences via the ctags index."""
        return analysis_operators.read_ctag_symbol(symbol_name)


    def add_condition_constraint_Tool(self, raw_expression: str, expect_result: bool, location: str, description: str = ""):
        """
        Record a condition constraint extracted from the path.
        
        Args:
            raw_expression: The raw condition expression (e.g., "x > 5").
            expect_result: The expected boolean result (True/False) for the path to be taken.
            location: The source location (file:line).
            description: Optional description of the constraint.
        """
        constraint = {
            "type": "condition",
            "raw_expression": raw_expression,
            "expect_result": expect_result,
            "location": location,
            "description": description
        }
        self.execution_trace.append(constraint)
        return f"Added constraint: {json.dumps(constraint)}"

    def deconstruct_condition_constraint_Tool(self, original_expression: str, simplified_constraints: List[str], location: str):
        """
        Deconstruct a complex condition into simpler constraints solvable by Z3.
        
        Args:
            original_expression: The complex expression (e.g., "complex_func(x)").
            simplified_constraints: List of simpler Z3-compatible constraints (e.g., ["ret_val == 1", "x > 0"]).
            location: The source location.
        """
        constraint = {
            "type": "deconstructed",
            "original_expression": original_expression,
            "simplified_constraints": simplified_constraints,
            "location": location
        }
        self.execution_trace.append(constraint)
        return f"Deconstructed constraint: {json.dumps(constraint)}"

    def add_relevant_operation_Tool(self, code: str, description: str, location: str):
        """
        Record an operation that affects values used in conditions (assignments, function calls, etc.).
        
        Args:
            code: The code snippet of the operation.
            description: Description of the impact on values.
            location: The source location.
        """
        operation = {
            "type": "operation",
            "code": code,
            "description": description,
            "location": location
        }
        self.execution_trace.append(operation)
        return f"Recorded operation: {json.dumps(operation)}"

    def _build_path_context(self, path_entry: Dict[str, Any]) -> str:
        """
        Build a context description for the path to help the LLM understand the flow.
        """
        path_id = path_entry.get("path_id", "unknown")
        path_node_list = path_entry.get("path_node_list", [])
        
        context_parts = [f"Path (path_id: {path_id}):"]
        
        for i, node in enumerate(path_node_list):
            node_type = node.get("node", "")
            location = node.get("location", "")
            code_line = find_code_line(location) if location else ""
            
            if node_type == "branch":
                condition_value = node.get("condition_value")
                expression = node.get("expression", "")
                context_parts.append(f"[{i}] Branch at {location}:")
                context_parts.append(f"    Code: {code_line}")
                context_parts.append(f"    Expression: {expression}")
                context_parts.append(f"    Taken Branch Value: {condition_value}")
            elif location and code_line:
                context_parts.append(f"[{i}] {node_type} at {location}: {code_line}")
        
        return "\n".join(context_parts)

    def extract_path_constraints(self, path_id: str) -> Optional[Dict[str, Any]]:
        """
        Analyze the path and extract/deconstruct constraints.
        Returns the enriched path entry.
        """
        self.current_path_id = path_id
        self.execution_trace = []
        
        path_entry = next((p for p in self.path_data if str(p.get("path_id")) == str(path_id)), None)
        if not path_entry:
            logger.error(f"Path ID {path_id} not found.")
            return None
            
        path_context = self._build_path_context(path_entry)
        
        system_prompt = (
            "You are a Path Branch Extractor Agent. Your goal is to analyze an execution path and generate an ordered execution trace for verification.\n"
            "You need to help the Z3 solver by explicitly identifying conditions AND the operations that affect them.\n\n"
            "TASKS:\n"
            "1. **Trace Execution**: Walk through the path step-by-step in execution order.\n"
            "2. **Record Relevant Operations**: If you encounter assignments, function calls, or modifications that affect variables used in later conditions:\n"
            "   - Use `add_relevant_operation` to record the code and its impact.\n"
            "   - Example: `x = get_value()` or `x++`.\n"
            "3. **Identify Constraints**: For every branch in the path, identify the condition that must hold.\n"
            "   - Use `add_condition_constraint` to record the expression and the expected result (True/False).\n"
            "4. **Deconstruct Complex Conditions**: If a condition involves complex function calls, macros, or logic:\n"
            "   - Break it down into simpler logical assertions.\n"
            "   - Use `deconstruct_condition_constraint` to provide a list of simplified constraints.\n"
            "   - Example: `if (check_valid(x))` -> might imply `x != NULL` and `x->valid == 1`.\n"
            "\n"
            "Use the provided tools to inspect code context if needed (`dump_source_snippet`, `read_ctag_symbol`).\n"
            "Ensure the output sequence (constraints + operations) logically follows the path execution."
        )
        print(f"[PathBranchExtractor] System prompt: {system_prompt}")
        
        user_message = (
            f"Analyze the following path and extract the execution trace (operations and constraints):\n\n"
            f"{path_context}\n"
        )
        print(f"[PathBranchExtractor] User message: {user_message}")
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        self._run_conversation(messages)
        
        # Enrich the path entry with extracted constraints
        # We can add a new field 'extracted_constraints' to the path entry
        # or merge it into the path_node_list if possible, but a separate list is cleaner for now.
        path_entry['execution_trace'] = self.execution_trace
        
        return path_entry

    def _run_conversation(self, messages):
        """Helper to run the LLM conversation loop."""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "dump_source_snippet",
                    "description": "Get source code snippet",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_name": {"type": "string"},
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"}
                        },
                        "required": ["file_name", "start_line", "end_line"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "read_ctag_symbol",
                    "description": "Look up symbol definitions and references using the pre-generated ctags index for the PUT project.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbol_name": {
                                "type": "string",
                                "description": "Identifier to search for."
                            }
                        },
                        "required": ["symbol_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "add_condition_constraint",
                    "description": "Add a condition constraint extracted from the path",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "raw_expression": {"type": "string", "description": "The raw condition expression"},
                            "expect_result": {"type": "boolean", "description": "The expected result (True/False)"},
                            "location": {"type": "string", "description": "Source location"},
                            "description": {"type": "string", "description": "Description of the constraint"}
                        },
                        "required": ["raw_expression", "expect_result", "location"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "deconstruct_condition_constraint",
                    "description": "Deconstruct a complex condition into simpler Z3-compatible constraints",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "original_expression": {"type": "string", "description": "The original complex expression"},
                            "simplified_constraints": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of simplified constraints"
                            },
                            "location": {"type": "string", "description": "Source location"}
                        },
                        "required": ["original_expression", "simplified_constraints", "location"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "add_relevant_operation",
                    "description": "Record an operation that affects values used in conditions (assignments, function calls, etc.)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "The code snippet of the operation"},
                            "description": {"type": "string", "description": "Description of the impact on values"},
                            "location": {"type": "string", "description": "Source location"}
                        },
                        "required": ["code", "description", "location"]
                    }
                }
            }
        ]
        
        # Limit turns to prevent infinite loops, though typically it finishes in one or two goes.
        max_turns = 100
        turn = 0
        
        while turn < max_turns:
            turn += 1
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            
            response_message = response.choices[0].message
            tool_calls = response_message.tool_calls
            
            if not tool_calls:
                # Agent is done
                break
                
            messages.append(response_message)
            
            for tool_call in tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                print(f"[PathBranchExtractor] Calling tool: {function_name} args: {function_args}")
                
                function_to_call = self.tool_method_map.get(function_name)
                if function_to_call:
                    try:
                        function_response = str(function_to_call(**function_args))
                    except Exception as e:
                        function_response = f"Error executing {function_name}: {str(e)}"
                else:
                    function_response = f"Error: Tool {function_name} not found"
                
                print(f"[PathBranchExtractor] Function response: {function_response}")
                
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": function_response
                })


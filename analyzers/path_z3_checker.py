import os
import json
import logging
import re
import subprocess
from typing import List, Dict, Any, Optional

from openai import OpenAI
import analysis_operators
from utils import find_code_line

logger = logging.getLogger(__name__)

class PathZ3CheckerAgent:
    """
    PathZ3Checker Agent
    
    Generates Python Z3 scripts to verify path feasibility based on branch conditions.
    """
    
    Z3_SCRIPT_TEMPLATE = """import json

from z3 import *

def solve():
    s = Solver()

    # ------------- Placeholder: Insert Agent-generated code here -------------
    # {{ AGENT_GENERATED_CODE }}
    # ------------------------------------------------------------------------

    result = s.check()

    if result == sat:
        m = s.model()
        return {"status": "sat", "model": {d.name(): str(m[d]) for d in m}}
    elif result == unsat:
        return {"status": "unsat", "core": []}
    else:
        return {"status": "unknown"}

if __name__ == "__main__":
    print(json.dumps(solve()))
"""
    
    def __init__(self, path_data: List[Dict[str, Any]], client: Optional[OpenAI] = None, model_name: str = "gpt-4"):
        """
        Initialize the PathZ3CheckerAgent.
        
        Args:
            path_data: List of path data dictionaries.
            client: OpenAI client instance.
            model_name: Name of the model to use.
        """
        self.path_data = path_data
        self.client = client
        self.model_name = model_name
        self.current_path_id = None  # Track the current path being processed
        
        # Tool method mapping
        self.tool_method_map = {
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
            "get_local_var_type": self.get_local_var_type_Tool,
            "read_ctag_symbol": self.read_ctag_symbol_Tool,
            "save_z3_script": self.save_z3_script_Tool,
            "read_z3_script": self.read_z3_script_Tool,
            "patch_code": self.patch_code_Tool,
            "run_z3_script": self.run_z3_script_Tool,
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
    
    def find_current_function_Tool(self, source_location):
        """Find the function containing the source location."""
        return analysis_operators.find_current_function(source_location)
    
    def find_function_body_Tool(self, function_name):
        """Find the body of a function."""
        return analysis_operators.find_function_body(function_name)
    
    def find_callers_Tool(self, function_name):
        """Find callers of a function."""
        return analysis_operators.find_callers(function_name)
    
    def get_local_var_type_Tool(self, function_name, var_name):
        """Retrieve the type and definition information for a local variable."""
        return analysis_operators.get_local_var_type(function_name, var_name)

    def _generate_filename(self) -> str:
        """
        Generate filename based on current_path_id.
        
        Returns:
            The generated filename.
        """
        if self.current_path_id is not None:
            # Find the path entry to get additional info if needed
            path_entry = next((p for p in self.path_data if str(p.get("path_id")) == str(self.current_path_id)), None)
            # print(f"Path entry: {path_entry}")
            if path_entry:
                # Extract source location if available for more descriptive filename
                path_node_list = path_entry.get("path_node_list", [])
                if path_node_list:
                    start_location = path_node_list[0].get("location", "")
                else:
                    start_location = ""
                if start_location:
                    # Format: path_{path_id}_{filename}_{line}.py
                    # Example: path_1_tif_dirwrite_839.py
                    # Sanitize the location string to make it filename-safe
                    # Remove directory separators, keep only basename
                    location_basename = os.path.basename(start_location)
                    # Replace colons, dots, and other special chars with underscores
                    location_parts = location_basename.replace(":", "_").replace(".", "_")
                    print(f"Generated filename: path_{self.current_path_id}_{location_parts}.py")
                    return f"path_{self.current_path_id}_{location_parts}.py"
                else:
                    print(f"Generated filename: path_{self.current_path_id}_check.py")
                    return f"path_{self.current_path_id}_check.py"
            else:
                print(f"Generated filename: path_{self.current_path_id}_check.py")
                return f"path_{self.current_path_id}_check.py"
        else:
            # Fallback if no current_path_id is set
            print(f"Generated filename: path_unknown_check.py")
            return "path_unknown_check.py"

    def _initialize_template_file(self) -> str:
        """
        Initialize a template file with the placeholder. This should be called at the start of generate_z3_script.
        
        Returns:
            The filename of the created file.
        """
        # Ensure directory exists
        base_dir = os.path.join(os.getcwd(), "RES", "RUN", "z3_scripts")
        os.makedirs(base_dir, exist_ok=True)
        
        # Generate filename
        filename = self._generate_filename()
        file_path = os.path.join(base_dir, os.path.basename(filename))
        
        # Create file with template (placeholder will be empty initially or contain a comment)
        initial_code = "# TODO: Add Z3 constraints here\n    # Variable definitions and s.add() calls go here"
        script_content = self.Z3_SCRIPT_TEMPLATE.replace("{{ AGENT_GENERATED_CODE }}", initial_code)
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            logger.info(f"Initialized template file: {file_path}")
            return filename
        except Exception as e:
            logger.error(f"Error initializing template file: {str(e)}")
            raise

    def save_z3_script_Tool(self, agent_code: str) -> str:
        """
        Update the Z3 script by replacing the placeholder code in the existing template file.
        The file should already exist (created during initialization). This tool finds the placeholder
        section and replaces it with the provided agent_code.
        The filename is automatically generated based on path_data.
        
        Args:
            agent_code: The code to be inserted into the template (constraints and variable definitions).
            
        Returns:
            Success message with full path.
        """
        # Ensure directory exists
        base_dir = os.path.join(os.getcwd(), "RES", "RUN", "z3_scripts")
        os.makedirs(base_dir, exist_ok=True)
        
        # Generate filename
        filename = self._generate_filename()
        file_path = os.path.join(base_dir, os.path.basename(filename))
        
        try:
            # Read existing file (should exist from initialization)
            if not os.path.exists(file_path):
                # If file doesn't exist, create from template (fallback)
                script_content = self.Z3_SCRIPT_TEMPLATE.replace("{{ AGENT_GENERATED_CODE }}", agent_code)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(script_content)
                return f"Successfully created Z3 script at {file_path}"
            
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()
            
            # Find the placeholder section between the comment markers
            marker_start = "# --- 占位符：这里插入 Agent 生成的代码 ---"
            marker_end = "# ------------------------------------"
            
            if marker_start in file_content and marker_end in file_content:
                # Find the section between markers
                start_idx = file_content.find(marker_start)
                end_idx = file_content.find(marker_end)
                
                if start_idx < end_idx:
                    # Extract the line before marker_start to get indentation
                    lines_before = file_content[:start_idx].split('\n')
                    if lines_before:
                        # Get indentation from the last non-empty line before the marker
                        for line in reversed(lines_before):
                            if line.strip():
                                indent = len(line) - len(line.lstrip())
                                break
                        else:
                            indent = 4  # Default indentation
                    else:
                        indent = 4
                    
                    # Apply indentation to agent_code
                    indented_code = '\n'.join(
                        ' ' * indent + line if line.strip() else ''
                        for line in agent_code.split('\n')
                    )
                    
                    # Replace the content between markers (including the markers themselves)
                    # Keep the markers and insert code between them
                    before_marker = file_content[:start_idx + len(marker_start)]
                    after_marker = file_content[end_idx:]
                    
                    # Reconstruct with new code
                    file_content = before_marker + "\n" + indented_code + "\n    " + after_marker
                else:
                    # Markers found but in wrong order, fallback to template replacement
                    script_content = self.Z3_SCRIPT_TEMPLATE.replace("{{ AGENT_GENERATED_CODE }}", agent_code)
                    file_content = script_content
            else:
                # Markers not found, try to find TODO comment pattern
                todo_pattern = r"# TODO: Add Z3 constraints here.*?# Variable definitions and s\.add\(\) calls go here"
                match = re.search(todo_pattern, file_content, re.DOTALL)
                if match:
                    # Extract indentation
                    lines_before = file_content[:match.start()].split('\n')
                    if lines_before:
                        last_line = lines_before[-1]
                        indent = len(last_line) - len(last_line.lstrip())
                    else:
                        indent = 4
                    
                    indented_code = '\n'.join(
                        ' ' * indent + line if line.strip() else ''
                        for line in agent_code.split('\n')
                    )
                    file_content = re.sub(todo_pattern, indented_code, file_content, flags=re.DOTALL)
                else:
                    # No placeholder found, fallback to template replacement
                    script_content = self.Z3_SCRIPT_TEMPLATE.replace("{{ AGENT_GENERATED_CODE }}", agent_code)
                    file_content = script_content
            
            # Write the updated content
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(file_content)
            return f"Successfully updated Z3 script at {file_path}"
        except Exception as e:
            return f"Error saving file: {str(e)}"

    def read_z3_script_Tool(self, filename: str) -> str:
        """
        Read the content of an existing Z3 script.
        
        Args:
            filename: Name of the file to read (e.g., "verification_path_1.py").
                      Expected to be in 'RES/RUN/z3_scripts' directory.
            
        Returns:
            Content of the file or error message.
        """
        base_dir = os.path.join(os.getcwd(), "RES", "RUN", "z3_scripts")
        file_path = os.path.join(base_dir, os.path.basename(filename))
        
        if not os.path.exists(file_path):
            return f"Error: File {filename} does not exist in {base_dir}"
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def patch_code_Tool(self, filename: str, old_code: str, new_code: str) -> str:
        """
        Patch (modify) code in a Z3 script file by replacing a code snippet.
        
        Args:
            filename: Name of the Z3 script file to modify (e.g., "path_1_check.py").
                      Expected to be in 'RES/RUN/z3_scripts' directory.
            old_code: The original code snippet to be replaced (exact match required).
            new_code: The new code snippet to replace the old one.
            
        Returns:
            Success message with details, or error message if the operation fails.
        """
        base_dir = os.path.join(os.getcwd(), "RES", "RUN", "z3_scripts")
        file_path = os.path.join(base_dir, os.path.basename(filename))
        
        if not os.path.exists(file_path):
            return f"Error: File {filename} does not exist in {base_dir}"
        
        try:
            # Read the current file content
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()
            
            # Check if old_code exists in the file
            if old_code not in file_content:
                return f"Error: The specified code snippet was not found in {filename}. Please ensure the old_code exactly matches the code in the file (including whitespace and indentation)."
            
            # Replace the old code with new code
            new_content = file_content.replace(old_code, new_code, 1)  # Replace only the first occurrence
            
            # Write back to file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            
            return f"Successfully patched {filename}. Replaced the specified code snippet."
        except Exception as e:
            return f"Error patching file: {str(e)}"

    def run_z3_script_Tool(self, filename: Optional[str] = None) -> str:
        """
        Run a Z3 script and capture its output. If filename is not provided, uses the current path's script.
        
        Args:
            filename: Optional name of the Z3 script file to run (e.g., "path_1_check.py").
                     If not provided, automatically uses the script for the current path.
                     Expected to be in 'RES/RUN/z3_scripts' directory.
            
        Returns:
            Formatted execution result including status, stdout, stderr, and return code.
        """
        base_dir = os.path.join(os.getcwd(), "RES", "RUN", "z3_scripts")
        
        # If filename not provided, generate it based on current_path_id
        if filename is None:
            if self.current_path_id is not None:
                filename = self._generate_filename()
            else:
                msg = "Error: No filename provided and current_path_id is not set. Cannot determine which script to run."
                logger.error(msg)
                return msg
        
        file_path = os.path.join(base_dir, os.path.basename(filename))
        
        if not os.path.exists(file_path):
            msg = f"Error: File {filename} does not exist in {base_dir}"
            logger.error(msg)
            return msg
        
        try:
            # Run the script with subprocess
            result = subprocess.run(
                ["python3", file_path],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=base_dir
            )
            
            # Parse JSON output if possible
            stdout_json = None
            try:
                if result.stdout.strip():
                    stdout_json = json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                pass
            
            # Format the result with prominent output
            status = "success" if result.returncode == 0 else "error"
            status_symbol = "✓" if result.returncode == 0 else "✗"
            
            # Create prominent debug output
            print(f"\n{'#'*80}")
            print(f"# [Z3 Script Execution Result] {status_symbol} {status.upper()}")
            print(f"{'#'*80}")
            print(f"# Script: {filename}")
            print(f"# Return Code: {result.returncode}")
            print(f"{'#'*80}")
            
            if result.stdout:
                print(f"\n{'─'*80}")
                print("STDOUT:")
                print(f"{'─'*80}")
                print(result.stdout)
                print(f"{'─'*80}")
            
            if result.stderr:
                print(f"\n{'─'*80}")
                print("STDERR:")
                print(f"{'─'*80}")
                print(result.stderr)
                print(f"{'─'*80}")
            
            if stdout_json:
                print(f"\n{'─'*80}")
                print("Parsed JSON Output:")
                print(f"{'─'*80}")
                print(json.dumps(stdout_json, indent=2))
                print(f"{'─'*80}")
            
            print(f"\n{'#'*80}\n")
            
            # Format the result message for return
            result_msg = f"Execution {status} (return code: {result.returncode})\n"
            result_msg += f"STDOUT:\n{result.stdout}\n"
            
            if result.stderr:
                result_msg += f"STDERR:\n{result.stderr}\n"
            
            if stdout_json:
                result_msg += f"Parsed JSON output:\n{json.dumps(stdout_json, indent=2)}\n"
            
            logger.info("run_z3_script_Tool result for %s:\n%s", filename, result_msg.strip())
            return result_msg
            
        except subprocess.TimeoutExpired:
            msg = f"Error: Script execution timed out after 30 seconds for {filename}"
            logger.error(msg)
            return msg
        except Exception as e:
            msg = f"Error running script {filename}: {str(e)}"
            logger.error(msg)
            return msg

    def send_message(self, messages, tools=None):
        """
        Send a message to the LLM and handle tool calls.
        """
        if not self.client:
            raise ValueError("OpenAI client is not initialized.")

        # Define available tools if not provided
        if tools is None:
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
                        "name": "dump_source_line",
                        "description": "Get single line of source code",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "file_name": {"type": "string"},
                                "line_number": {"type": "integer"}
                            },
                            "required": ["file_name", "line_number"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "find_current_function",
                        "description": "Find the function containing the source location",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_location": {"type": "string"}
                            },
                            "required": ["source_location"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "find_function_body",
                        "description": "Find the body of a function",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "function_name": {"type": "string"}
                            },
                            "required": ["function_name"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "find_callers",
                        "description": "Find callers of a function",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "function_name": {"type": "string"}
                            },
                            "required": ["function_name"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "get_local_var_type",
                        "description": "Retrieves the type and definition information for a local variable within a specific function. This tool parses the function's source code using tree-sitter to locate the variable declaration and extract its type information, location, and the actual code line where it is declared.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "function_name": {
                                    "type": "string",
                                    "description": "The name of the function containing the local variable. Must be a non-empty string and match an existing function in the codebase."
                                },
                                "var_name": {
                                    "type": "string",
                                    "description": "The name of the local variable to look up. Must be a non-empty string and must be declared within the specified function."
                                }
                            },
                            "required": ["function_name", "var_name"]
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
                        "name": "save_z3_script",
                        "description": "Save the Z3 script to a file. The filename will be automatically generated based on the path information. The agent_code parameter should contain only the constraint code to be inserted into the template (variable definitions and constraints), not the full script. Overwrites if exists.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "agent_code": {"type": "string", "description": "The code to be inserted into the template (constraints and variable definitions). This will replace the {{ AGENT_GENERATED_CODE }} placeholder in the template."}
                            },
                            "required": ["agent_code"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "read_z3_script",
                        "description": "Read the content of an existing Z3 script.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "filename": {"type": "string", "description": "Filename to read"}
                            },
                            "required": ["filename"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "patch_code",
                        "description": "Patch (modify) code in a Z3 script file by replacing a code snippet. Use this tool to make targeted changes to an existing Z3 script without rewriting the entire file. The old_code must exactly match the code in the file (including whitespace and indentation).",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "filename": {"type": "string", "description": "Name of the Z3 script file to modify (e.g., 'path_1_check.py'). Expected to be in 'RES/RUN/z3_scripts' directory."},
                                "old_code": {"type": "string", "description": "The original code snippet to be replaced. Must exactly match the code in the file, including all whitespace, indentation, and special characters."},
                                "new_code": {"type": "string", "description": "The new code snippet to replace the old one."}
                            },
                            "required": ["filename", "old_code", "new_code"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "run_z3_script",
                        "description": "Run a Z3 script and capture its output. If filename is not provided, automatically uses the script for the current path being processed. This tool executes the Python script and returns the execution results including stdout, stderr, and return code. Use this to test and verify your Z3 scripts.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "filename": {"type": "string", "description": "Optional name of the Z3 script file to run (e.g., 'path_1_check.py'). If not provided, uses the current path's script. Expected to be in 'RES/RUN/z3_scripts' directory."}
                            },
                            "required": []
                        }
                    }
                }
            ]

        while True:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            
            # Debug output for latest message content (if it's a user or system message added before this call)
            if len(messages) > 0:
                last_msg = messages[-1]
                if last_msg.get("role") == "user":
                    print(f"\n[PathZ3Checker] User Prompt:\n{last_msg.get('content')}\n{'-'*40}")
                elif last_msg.get("role") == "system":
                    print(f"\n[PathZ3Checker] System Prompt:\n{last_msg.get('content')}\n{'-'*40}")
            
            response_message = response.choices[0].message
            tool_calls = response_message.tool_calls
            
            # Debug output for model response
            print(f"[PathZ3Checker] Model Response:")
            if response_message.content:
                print(f"Content:\n{response_message.content}")
            if tool_calls:
                print(f"\nTool Calls ({len(tool_calls)}):")
                for i, tool_call in enumerate(tool_calls, 1):
                    print(f"  [{i}] {tool_call.function.name}")
                    print(f"      Args: {tool_call.function.arguments}")
            if not response_message.content and not tool_calls:
                print("(Empty response)")
            
            if not tool_calls:
                return response_message

            messages.append(response_message)
            
            for tool_call in tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                print(f"[PathZ3Checker] Calling tool: {function_name} with args: {function_args}")
                logger.info(f"Calling tool {function_name} with args {function_args}")
                
                function_to_call = self.tool_method_map.get(function_name)
                if function_to_call:
                    try:
                        function_response = str(function_to_call(**function_args))
                    except Exception as e:
                        function_response = f"Error executing {function_name}: {str(e)}"
                else:
                    function_response = f"Error: Tool {function_name} not found"
                print(f"[PathZ3Checker] Function response: {function_response}")
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": function_response
                })

    def _build_path_description(self, path_entry: Dict[str, Any]) -> str:
        """
        Build a detailed path description using the same logic as path_builder_agent.
        Extracts start/end nodes and branch conditions with code lines.
        """
        loop_pattern = re.compile(r"^\s*(for|while)\s*\(")
        
        def format_branch_condition(expression: str, value: Any) -> str:
            """
            Convert condition to assume form, value being True means directly assume expression holds,
            otherwise assume its negation holds. Default to assume(expr) if cannot determine.
            """
            expr_text = expression or "<unknown condition>"
            normalized = None
            if isinstance(value, bool):
                normalized = value
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "1", "yes"}:
                    normalized = True
                elif lowered in {"false", "0", "no"}:
                    normalized = False
            if normalized is True:
                if loop_pattern.match(expr_text):
                    return f"assume(loop iteration continues: {expr_text})"
                return f"assume({expr_text})"
            if normalized is False:
                if loop_pattern.match(expr_text):
                    return f"assume(after loop: {expr_text})"
                return f"assume(¬({expr_text}))"
            if loop_pattern.match(expr_text):
                return f"assume(loop branch: {expr_text})"
            return f"assume({expr_text})"
        
        path_id = path_entry.get("path_id", "unknown")
        path_node_list = path_entry.get("path_node_list", [])
        
        # Extract start and end nodes
        start_node = None
        end_node = None
        branch_conditions = []
        
        for node in path_node_list:
            node_type = node.get("node", "")
            location = node.get("location", "")
            
            if node_type == "start":
                start_node = location
                code_line = find_code_line(location) if location else ""
                if code_line:
                    start_node = f"{location} : {code_line}"
            
            if node_type == "return":
                end_node = location
                code_line = find_code_line(location) if location else ""
                if code_line:
                    end_node = f"{location} : {code_line}"
            
            if node_type == "branch":
                condition_value = node.get("condition_value")
                expression = node.get("expression")
                code_line = find_code_line(location) if location else ""
                
                if expression:
                    branch_conditions.append({
                        "location": location,
                        "expression": expression,
                        "value": condition_value,
                        "code_line": code_line
                    })
                elif code_line:
                    branch_conditions.append({
                        "location": location,
                        "expression": code_line,
                        "value": condition_value,
                        "code_line": code_line
                    })
        
        # Build path description
        description_parts = [f"Path (path_id: {path_id}):"]
        
        if start_node:
            description_parts.append(f"  Start: {start_node}")
        
        # List all branch conditions
        if branch_conditions:
            for i, cond in enumerate(branch_conditions, start=1):
                cond_str = format_branch_condition(cond["expression"], cond["value"])
                description_parts.append(f"  Branch {i}: {cond['location']}: {cond_str}")
        else:
            description_parts.append("  No branch constraints (direct path)")
            
        # Add extracted execution trace from PathBranchExtractorAgent
        execution_trace = path_entry.get("execution_trace", [])
        if not execution_trace:
            # Fallback to old field name if present
            execution_trace = path_entry.get("extracted_constraints", [])

        if execution_trace:
            description_parts.append("\n  Extracted Execution Trace:")
            for step in execution_trace:
                c_type = step.get("type")
                loc = step.get("location", "unknown")
                
                if c_type == "condition":
                    raw = step.get("raw_expression")
                    expect = step.get("expect_result")
                    desc = step.get("description", "")
                    description_parts.append(f"    - [Condition] at {loc}")
                    description_parts.append(f"      Expression: {raw}")
                    description_parts.append(f"      Expected: {expect}")
                    if desc:
                        description_parts.append(f"      Info: {desc}")
                
                elif c_type == "deconstructed":
                    orig = step.get("original_expression")
                    simplified = step.get("simplified_constraints", [])
                    description_parts.append(f"    - [Deconstructed] at {loc}")
                    description_parts.append(f"      Original: {orig}")
                    description_parts.append(f"      Simplified: {simplified}")
                
                elif c_type == "operation":
                    code = step.get("code")
                    desc = step.get("description")
                    description_parts.append(f"    - [Operation] at {loc}")
                    description_parts.append(f"      Code: {code}")
                    description_parts.append(f"      Impact: {desc}")

        if end_node:
            description_parts.append(f"  End: {end_node}")
        
        return "\n".join(description_parts)

    def generate_z3_script(self, path_id: str) -> Optional[str]:
        """
        Generate a Z3 script for the specified path.
        """
        print(f"[PathZ3Checker] Analyzing path {path_id}...")
        # Find the path
        path_entry = next((p for p in self.path_data if p.get("path_id") == str(path_id)), None)
        if not path_entry:
            logger.error(f"Path ID {path_id} not found.")
            return None
        
        # Set current_path_id so save_z3_script_Tool can use it to generate filename
        self.current_path_id = str(path_id)
        
        # Initialize template file and get the filename
        try:
            script_filename = self._initialize_template_file()
            print(f"[PathZ3Checker] Initialized template file: {script_filename}")
        except Exception as e:
            logger.error(f"Failed to initialize template file: {str(e)}")
            return None
            
        # Construct the system prompt
        system_prompt = (
            "You are a Rigorous Constraint Translator. Your SOLE purpose is to translate C/C++ path constraints into Z3 Python code exactly as they appear.\n"
            "You are NOT a developer trying to fix the code. You are NOT a logic reasoner trying to make the path feasible.\n"
            "### CRITICAL RULES FOR TRANSLATION ###\n"
            "1. **LITERAL TRANSLATION**: You must translate every single branch condition into a `s.add(...)` statement. \n"
            "   - If the path says 'assume(x > 0)' and later 'assume(x < 0)', you MUST add BOTH `s.add(x > 0)` and `s.add(x < 0)`.\n"
            "   - **NEVER** ignore a constraint because it contradicts a previous one.\n"
            "   - **NEVER** modify a constraint to make the path satisfiable.\n"
            "   - The goal is to let the Z3 Solver discover the contradiction (return 'unsat'), not for you to resolve it.\n\n"

            "2. **HANDLING NEGATIONS**: Pay close attention to `¬` and `!` symbols.\n"
            "   - `assume(¬(ptr == NULL))` must be translated as `s.add(ptr != 0)` (or distinct from null).\n"
            "   - `assume(¬(ptr != NULL))` must be translated as `s.add(ptr == 0)`.\n"
            "   - Do not simplify complex boolean logic unless you are 100% sure it preserves exact equivalence.\n\n"
            
            "3. **POINTER & NULL MODELING**:\n"
            "   - For pointer variables (like `dirmem`, `tif`), model them as BitVectors or Integers.\n"
            "   - Treat `NULL` as `0`.\n"
            "   - If the path implies `dirmem` is allocated (malloc), assume it is a distinct value/address, but adhere strictly to subsequent checks (e.g., if a later check says it is NULL, add that constraint too).\n\n"

            "4. **VARIABLE CONSISTENCY**:\n"
            "   - Ensure the Z3 variable name for a C variable remains consistent throughout the script.\n"
            "   - Do not create `dirmem_1` and `dirmem_2` unless the C code actually reassigns the variable. If it's the same variable scope, use the same Z3 variable.\n\n"
            "IMPORTANT: You will work with a pre-defined script template. A template file has already been created for you.\n"
            f"The script file name is: {script_filename}\n"
            "You should NOT generate the full script. Instead, you should only generate the constraint code that will be inserted into the template.\n\n"
            "You will be provided with a detailed path description containing branch conditions that must be satisfied for the path to be executable.\n"
            "The branch conditions are canonicalized constraints derived after clustering many concrete executions; they represent the shared assumptions for that path cluster.\n"
            "Consider a path feasible if there exists at least one real execution that can simultaneously satisfy all listed constraints.\n\n"
            "You should:\n"
            "1. Analyze the path constraints carefully, checking for conflicting constraints (e.g., 'x > 0' followed by 'x == 0').\n"
            "2. Use the provided tools to inspect the source code if necessary (e.g., to understand variable types, macro definitions, or context).\n"
            "3. Formulate the constraints in Z3.\n"
            "   - Create Z3 variables for the relevant C variables. Be mindful of types (BitVectors for integers, Bool for booleans, etc.).\n"
            "   - Add constraints for each branch condition on the path using s.add().\n"
            "   - Add constraints for any data flow relationships implied by the path.\n"
            "   - Handle loop conditions appropriately (consider loop iteration vs. loop exit).\n"
            f"4. Use the `save_z3_script` tool with ONLY the constraint code (variable definitions and s.add() calls) to update the file '{script_filename}'. "
            "   The tool will automatically insert your code into the template.\n"
            f"5. After saving, use `run_z3_script` to test the script '{script_filename}' and verify it works correctly.\n"
            f"6. If the script has errors or needs modification, use `read_z3_script` to see the current code in '{script_filename}', "
            "then use `patch_code` to make targeted changes.\n"
            "7. The template handles:\n"
            "   - Importing z3 and json\n"
            "   - Initializing the Solver\n"
            "   - Checking satisfiability\n"
            "   - Formatting output as JSON\n"
            "   - Your code should only contain variable definitions and constraint additions (s.add(...)).\n"
            "8. The output format is automatically handled by the template and will be JSON with status and model fields.\n"
            "9. If the path has conflicting constraints, the solver will return 'unsat', indicating the path is not feasible.\n"
        )
        
        # Build detailed path description using the same logic as path_builder_agent
        path_description = self._build_path_description(path_entry)
        
        user_message = (
            f"Please generate a Z3 verification script for the following path:\n\n"
            f"{path_description}\n\n"
            f"Analyze the branch constraints and create Z3 variables and constraints to verify whether this path is feasible."
        )
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        
        # Start the conversation
        final_response = self.send_message(messages)
        return final_response.content



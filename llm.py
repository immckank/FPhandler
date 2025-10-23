from google import genai
from google.genai import types
from pydantic import BaseModel
from openai import OpenAI

import json
import os
import logging

from analysis_operators import *
from config import *
from utils import *
from prompts import *
import re

class judgeResult(BaseModel):
    classification: str
    reasoning: str

class AnalysisModel():
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis") 
        self.result_logger = setup_logger(log_type="result")
        pass
    
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None

    def responseForAlter(self, alter_prompt, user_prompt=""):
        return None

class Gemini(AnalysisModel):
    def __init__(self, model_name="gemini-2.5-flash"):
        super().__init__()
        self.model_name = model_name
                 
    def resposeToAlter(self, alter_prompt, user_prompt=""):
        config = types.GenerateContentConfig(
            system_instruction=SYS_PROMPT+ASSUMPTION_PROMPT,
            response_schema=judgeResult,
            response_mime_type="application/json",
        )
        client = genai.Client()
        response = client.models.generate_content(
            model=self.model_name,
            contents=alter_prompt + "\n" + user_prompt,
            config=config
        )
        return response.text
    
    def responseForAlter(self, alter_prompt, user_prompt="", allowed_tool_names = []):
        allowed_tools = []
        for tool_name in allowed_tool_names:
            if tool_name == "dump_source_snippet":
                allowed_tools.append(dump_source_snippet)
            elif tool_name == "dump_source_line":
                allowed_tools.append(dump_source_line)
            elif tool_name == "find_callee":
                allowed_tools.append(find_callee)
            elif tool_name == "find_current_function":
                allowed_tools.append(find_current_function)
            elif tool_name == "find_callers":
                allowed_tools.append(find_callers)
            elif tool_name == "find_function_body":
                allowed_tools.append(find_function_body)
            elif tool_name == "get_path_cond_func":
                allowed_tools.append(get_path_cond_func)
            else:
                raise ValueError(f"Unknown tool name: {tool_name}")
        config = types.GenerateContentConfig(
            system_instruction=SYS_PROMPT+ASSUMPTION_PROMPT,
            # response_schema=judgeResult,
            # response_mime_type="application/json",
            tools=allowed_tools
        )
        client = genai.Client()
        response = client.models.generate_content(
            model=self.model_name,
            contents=Alter_prompt + "\n" + user_prompt,
            config=config
        )
        return response
    
class DeepSeek(AnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        
    def send_message(self, messages, tools=""):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        return response.choices[0].message     
            
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter_prompt, user_prompt="", allowed_tool_names = []):
        allowed_tools = []
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "set_conclusion",
                "description": "Sets the final conclusion for an alert analysis. This function should be called at the end of an analysis to provide a definitive classification and the reasoning behind it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "classification": {
                            "type": "string",
                            "description": "The classification of the alert, must be one of 'FP' (False Positive), 'TP' (True Positive), or 'UNCERTAIN'.",
                            "enum": ["FP", "TP", "UNCERTAIN"]
                        },
                        "reason": {
                            "type": "string",
                            "description": "A detailed explanation for the given classification."
                        }
                    },
                    "required": ["classification", "reason"]
                }
            }
        })
        for tool_name in allowed_tool_names:
            if tool_name == "dump_source_snippet":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "dump_source_snippet",
                        "description": "Dumps a snippet of source code from a file between the given line numbers.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                                "start_line": {"type": "integer", "description": "The starting line number (inclusive)."},
                                "end_line": {"type": "integer", "description": "The ending line number (inclusive)."}
                            },
                            "required": ["file_name", "start_line", "end_line"]
                        }
                    }
                })
            elif tool_name == "dump_source_line":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "dump_source_line",
                        "description": "Dumps a single line of source code from a file.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                                "line_number": {"type": "integer", "description": "The line number to retrieve."}
                            },
                            "required": ["file_name", "line_number"]
                        }
                    }
                })
            elif tool_name == "find_callee":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_callee",
                        "description": "Finds the function body of functions called at a specific source location.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_location": {"type": "string", "description": "The source location of the call site, in the format 'filename.c:line_number'."}
                            },
                            "required": ["source_location"]
                        }
                    }
                })
            elif tool_name == "find_current_function":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_current_function",
                        "description": "Finds the function in which the given source location exists.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_location": {"type": "string", "description": "The source location, in the format 'filename.c:line_number'."}
                            },
                            "required": ["source_location"]
                        }
                    }
                })
            elif tool_name == "find_callers":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_callers",
                        "description": "Finds all functions that call a given target function.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "function_name": {"type": "string", "description": "The name of the target function to find callers for."}
                            },
                            "required": ["function_name"]
                        }
                    }
                })
            elif tool_name == "find_function_body":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_function_body",
                        "description": "Finds the function body by its name.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "function_name": {"type": "string", "description": "The name of the function to find."}
                            },
                            "required": ["function_name"]
                        }
                    }
                })
            elif tool_name == "get_path_cond_func":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "get_path_cond_func_",
                        "description": "Finds all paths between a start and target location, collecting information about function calls and conditional branches along the way.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "start_location": {"type": "string", "description": "The start source location, in 'filename.c:line_number' format."},
                                "start_code": {"type": "string", "description": "The source code of the start location."},
                                "target_location": {"type": "string", "description": "The target source location, in 'filename.c:line_number' format."},
                                "target_code": {"type": "string", "description": "The source code of the target location."}
                            },
                            "required": ["start_location", "start_code", "target_location", "target_code"]
                        }
                    }
                })
            elif tool_name == "find_var_definitions":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_var_definitions",
                        "description": "Finds all definitions of a given variable across the project.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_location": {
                                    "type": "string",
                                    "description": "The source location to provide context, in the format 'filename.c:line_number'."
                                },
                                "var_name": {
                                    "type": "string",
                                    "description": "The name of the variable to find definitions for."
                                }
                            },
                            "required": ["source_location", "var_name"]
                        }
                    }
                })
            elif tool_name == "find_var_decl":
                allowed_tools.append({
                    "type": "function",
                    "function": {
                        "name": "find_var_decl",
                        "description": "Finds all declarations of a given identifier across the project.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source_location": {"type": "string", "description": "A source location within the project to provide context, in format 'filename.c:line_number'."},
                                "var_name": {"type": "string", "description": "The name of the identifier to find declarations for."}
                            },
                            "required": ["source_location", "var_name"]
                        }
                    }
                })
            else:
                raise ValueError(f"Unknown tool name: {tool_name}")
        prompt = alter_prompt + "\n" + user_prompt
        self.analysis_logger.info(f"Prompt: {prompt}")
        self.result_logger.info(f"Prompt: {prompt}")
        self.result_logger.info(f"Index: {alter_index}")
        messages = [
            {"role": "system", "content": SYS_PROMPT+ASSUMPTION_PROMPT},
            {"role": "user", "content": prompt}
        ]
        response = self.send_message(messages, allowed_tools)
        self.analysis_logger.info(f"Model response: {response.content}")
        messages.append(response)
        while response.tool_calls:
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    # Log and respond with an error so the model can recover
                    self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                    function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                    messages.append(
                        {
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "content": function_response,
                        }
                    )
                    # ask the model for next action by continuing the loop
                    continue
                self.analysis_logger.info(f"Calling tool: {tool_function_name} with args: {tool_arguments}")
                if tool_function_name == "set_conclusion":
                    function_response = set_conclusion(**tool_arguments)
                    # function_response = json.loads(function_response)
                    # 查询response中有没有error字段
                    if "error" in function_response:
                        continue
                    else:
                        # 说明正常得出了结论 可以返回
                        self.analysis_logger.info(f"Tool response: {function_response}")
                        self.result_logger.info(f"{function_response}")
                        return
                if tool_function_name == "dump_source_snippet":
                    function_response = dump_source_snippet(**tool_arguments)
                elif tool_function_name == "dump_source_line":
                    function_response = dump_source_line(**tool_arguments)
                elif tool_function_name == "find_callee":
                    function_response = find_callee(**tool_arguments)
                elif tool_function_name == "find_current_function":
                    function_response = find_current_function(**tool_arguments)
                elif tool_function_name == "find_callers":
                    function_response = find_callers(**tool_arguments)
                elif tool_function_name == "find_function_body":
                    function_response = find_function_body(**tool_arguments)
                elif tool_function_name == "get_path_cond_func_":
                    function_response = get_path_cond_func_(**tool_arguments)
                elif tool_function_name == "find_var_definitions":
                    function_response = find_var_definitions(**tool_arguments)
                elif tool_function_name == "find_var_decl":
                    function_response = find_var_decl(**tool_arguments)
                else:
                    # It's good practice to handle unknown tool calls
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
                # Convert response to JSON string if it's not already a string
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                
                self.analysis_logger.info(f"Tool response: {function_response}")   
                messages.append(
                    {
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "content": function_response,
                    }
                )
            # Send the tool responses back to the model
            response = self.send_message(messages, allowed_tools)
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)
        return
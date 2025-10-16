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


class judgeResult(BaseModel):
    classification: str
    reasoning: str
    
# 你将以一步一步的方式分解问题，并通过“思考->行动->观察”的循环来推进。
# 在每一步，你都必须首先输出一个'Thought'，阐述你当前的分析和下一步计划。然后，你必须输出一个'Action'来执行你的计划。
# 当且仅当你收集到足够的信息来直接回答用户的问题时，你才能输出最终答案。

SYS_PROMPT = """
You are a software security researcher tasked with classifying SAST alerts on C code.
Each alert must be classified as one of: TP (true positive): the code violates the guidance provided by the user; FP (false positive): the code follows the guidance; UNCERTAIN: there isn't enough information to decide. 
Each user input will include: the bug type, source file name and line number of the potential bug, the alert message. 
You will break down the problem in a step-by-step manner and proceed using a "Thought->Action->Observation" loop.
In each step, you must first output a 'Thought' that explains your current analysis and your plan for the next step. Then, you must output an 'Action' to execute your plan.
You can output the final answer when, and only when, you have gathered enough information to directly answer the user's question.
Guidelines: Focus only on the specified bug type and location. Don't speculate about future code changes. Think step by step. Any factual information must be verified using tools and based on the source code instead of your internal knowledge. If you execute an action and do not get the expected result, you should analyze the reason in the next 'Thought' and try to solve the problem using a different method or tool. Do not repeat the exact same 'Action'. If the problem is beyond the capabilities of your tools, or if you have tried all possible methods and still cannot solve it, please state directly in the 'Final Answer' that you cannot answer the question.
"""

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
            system_instruction=SYS_PROMPT,
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
            system_instruction=SYS_PROMPT,
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
            else:
                raise ValueError(f"Unknown tool name: {tool_name}")
        prompt = alter_prompt + "\n" + user_prompt
        self.analysis_logger.info(f"Prompt: {prompt}")
        self.result_logger.info(f"Prompt: {prompt}")
        messages = [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": prompt}
        ]
        response = self.send_message(messages, allowed_tools)
        self.analysis_logger.info(f"Model response: {response.content}")
        messages.append(response)
        while response.tool_calls:
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                # print(tool_call.function.arguments)
                tool_arguments = json.loads(tool_call.function.arguments)
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
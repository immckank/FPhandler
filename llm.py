from google import genai
from google.genai import types
from abc import ABC, abstractmethod
from pydantic import BaseModel
from openai import OpenAI

import json
import os
import logging

import memory_defect

from analysis_operators import *
from config import *
from utils import *
from prompts import *
import re
from func_analyzer import (
    DeepSeekFunctionAnalyzer,
    QwenFunctionAnalyzer
)
from tools import (
    set_conclusion_desc_free,
    dump_source_snippet_desc_free,
    dump_source_line_desc_free,
    find_current_function_desc_free,
    find_function_body_desc_free,
    find_callers_desc_free
)

class judgeResult(BaseModel):
    classification: str
    reasoning: str

class FreeAnalysisModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis") 
        self.result_logger = setup_logger(log_type="result")
        self.tool_functions = {
            "set_conclusion": set_conclusion,
            "dump_source_snippet": dump_source_snippet,
            "dump_source_line": dump_source_line,
            "find_callee": find_callee,
            "find_current_function": find_current_function,
            "find_callers": find_callers,
            "find_function_body": find_function_body,
            "get_path_cond_func_": get_path_cond_func_,
            "find_var_definitions": find_var_definitions,
            "find_var_decl": find_var_decl,
        }   
        pass
    
    @abstractmethod
    def responseToAlter(self, alter_prompt, user_prompt=""):
        pass

    @abstractmethod
    def responseForAlter(self, alter):
        pass

class GeminiFreeAnalyzer(FreeAnalysisModel):
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
    
    def responseForAlter(self, alter, user_prompt="", allowed_tool_names = []):
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
            contents=alter.to_prompt() + "\n" + user_prompt,
            config=config
        )
        return response
    
class DeepSeekFreeAnalyzer(FreeAnalysisModel):
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
    
    def responseForAlter(self, alter:memory_defect.MemoryLeak):
        allowed_tools = [
            set_conclusion_desc_free, dump_source_snippet_desc_free, dump_source_line_desc_free, 
            find_current_function_desc_free, find_function_body_desc_free, find_callers_desc_free
        ]
        # unused tools
        # find callee
        # allowed_tools.append({
        #     "type": "function",
        #     "function": {
        #         "name": "find_callee",
        #         "description": "Finds the function body of functions called at a specific source location.",
        #         "parameters": {
        #             "type": "object",
        #             "properties": {
        #                 "source_location": {"type": "string", "description": "The source location of the call site, in the format 'filename.c:line_number'."}
        #             },
        #             "required": ["source_location"]
        #         }
        #     }
        # })
        # for tool_name in allowed_tool_names:
        #     elif tool_name == "get_path_cond_func":
        #         allowed_tools.append({
        #             "type": "function",
        #             "function": {
        #                 "name": "get_path_cond_func_",
        #                 "description": "Finds all paths between a start and target location, collecting information about function calls and conditional branches along the way.",
        #                 "parameters": {
        #                     "type": "object",
        #                     "properties": {
        #                         "start_location": {"type": "string", "description": "The start source location, in 'filename.c:line_number' format."},
        #                         "start_code": {"type": "string", "description": "The source code of the start location."},
        #                         "target_location": {"type": "string", "description": "The target source location, in 'filename.c:line_number' format."},
        #                         "target_code": {"type": "string", "description": "The source code of the target location."}
        #                     },
        #                     "required": ["start_location", "start_code", "target_location", "target_code"]
        #                 }
        #             }
        #         })
        #     elif tool_name == "find_var_definitions":
        #         allowed_tools.append({
        #             "type": "function",
        #             "function": {
        #                 "name": "find_var_definitions",
        #                 "description": "Finds all definitions of a given variable across the project.",
        #                 "parameters": {
        #                     "type": "object",
        #                     "properties": {
        #                         "source_location": {
        #                             "type": "string",
        #                             "description": "The source location to provide context, in the format 'filename.c:line_number'."
        #                         },
        #                         "var_name": {
        #                             "type": "string",
        #                             "description": "The name of the variable to find definitions for."
        #                         }
        #                     },
        #                     "required": ["source_location", "var_name"]
        #                 }
        #             }
        #         })
        #     elif tool_name == "find_var_decl":
        #         allowed_tools.append({
        #             "type": "function",
        #             "function": {
        #                 "name": "find_var_decl",
        #                 "description": "Finds all declarations of a given identifier across the project.",
        #                 "parameters": {
        #                     "type": "object",
        #                     "properties": {
        #                         "source_location": {"type": "string", "description": "A source location within the project to provide context, in format 'filename.c:line_number'."},
        #                         "var_name": {"type": "string", "description": "The name of the identifier to find declarations for."}
        #                     },
        #                     "required": ["source_location", "var_name"]
        #                 }
        #             }
        #         })
        #     else:
        #         raise ValueError(f"Unknown tool name: {tool_name}")
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"        
        self.analysis_logger.info(f"Prompt: {alter.to_prompt()}")
        self.result_logger.info(f"Prompt: {alter.to_prompt()}")
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT},
            {"role": "user", "content": alter.to_prompt() + "\n" + project_prompt}
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
                    if "error" in function_response:
                        continue
                    self.analysis_logger.info(f"Tool response: {function_response}")
                    self.result_logger.info(f"{function_response}")
                    return
                elif tool_function_name in self.tool_functions:
                    function_response = self.tool_functions[tool_function_name](**tool_arguments)
                else:
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

class QwenFreeAnalyzer(FreeAnalysisModel):
    def __init__(self, model_name="qwen3-max"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("QWEN_API_KEY"),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
    
    def get_response(self, messages, tools):
        completion = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools,
        )
        return completion.choices[0].message
        
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter:memory_defect.MemoryLeak):
        allowed_tools = [
            set_conclusion_desc_free, dump_source_snippet_desc_free, dump_source_line_desc_free, 
            find_current_function_desc_free, find_function_body_desc_free, find_callers_desc_free
        ]
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"        
        self.analysis_logger.info(f"Prompt: {alter.to_prompt()}")
        self.result_logger.info(f"Prompt: {alter.to_prompt()}")
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT},
            {"role": "user", "content": alter.to_prompt() + "\n" + project_prompt}
        ]
        response = self.get_response(messages, allowed_tools)
        if not response.content: response.content = ""
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
                    if "error" in function_response:
                        continue
                    self.analysis_logger.info(f"Tool response: {function_response}")
                    self.result_logger.info(f"{function_response}")
                    return
                elif tool_function_name in self.tool_functions:
                    function_response = self.tool_functions[tool_function_name](**tool_arguments)
                else:
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
            response = self.get_response(messages, allowed_tools)
            if not response.content: response.content = ""
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)
        return

def create_analyzer(analyzer_type: str) -> FreeAnalysisModel:
    """Factory function to create an analyzer based on its type."""
    if analyzer_type == "free":
        if LLM_TYPE == "Gemini":
            return GeminiFreeAnalyzer()
        elif LLM_TYPE == "DeepSeek":
            return DeepSeekFreeAnalyzer()
        elif LLM_TYPE == "Qwen":
            return QwenFreeAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    elif analyzer_type == "function":
        if LLM_TYPE == "DeepSeek":
            return DeepSeekFunctionAnalyzer()
        if LLM_TYPE == "Qwen":
            return QwenFunctionAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    else:
        raise ValueError(f"Unknown analyzer type: {analyzer_type}")
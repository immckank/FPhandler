# 更进一步的细化模型的任务 制作小部分的工作-》说明到一个ret位置 值对象状态如何

import os
import json
import logging

from config import *
from utils import *
from prompts import *
from call_graph import *
from alter_handler import AlterAnalyzer
from tools import (
    dump_source_snippet_desc_free,
    dump_source_line_desc_free,
    find_current_function_desc_free,
    find_function_body_desc_free,
    find_callers_desc_free,
    set_conclusion_desc_path
)
import re

from abc import ABC, abstractmethod
from openai import OpenAI
import memory_defect

import analysis_operators


class PathAnalyzerModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis")
        self.result_logger = setup_logger(log_type="result")
        self.return_locations = []
        self.tool_method_map = {
            "set_conclusion": self.set_conclusion_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
        }

    def send_message(self, messages, tools=""):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        return response.choices[0].message  
    
    def check_all_return_locations_done(self):
        for return_location in self.return_locations:
            if not return_location["done"]:
                return False
        return True
    
    def clear(self):
        self.return_locations = []
        
    def set_conclusion_Tool(self, classification, return_location, reason, arg=None):
        # print(f"set_conclusion_Tool: {classification}, {return_location}, {reason}, {arg}")
        valid_return_location = False
        # 匹配一遍return_location是否存在
        for t_return_location in self.return_locations:
            if t_return_location["location"] == return_location and not t_return_location["done"]:
                valid_return_location = True
                break
        if not valid_return_location:
            location_list = []
            for t_return_location in self.return_locations:
                if not t_return_location["done"]:
                    location_list.append(t_return_location["location"])
            return {"error": f"return location {return_location} not found in the return locations, you should use location in {location_list} to set conclusion."}
        if classification == "NullPointer":
            # 保持为空指针的场景下不需要arg 也不需要做特殊检查
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": None}
        elif classification == "Transferred":
            # 内存所有权的场景 要求的arg发生转移的代码行
            # arg匹配 filename.c/.h:line_number
            if arg is not None and not re.match(r'^[\w/]+\.(c|h):\d+$', arg):
                return {"error": f"invalid arg: {arg}"}
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": arg}
        elif classification == "Returned":
            # 内存被返回的场景 要求的arg返回的代码行
            # arg匹配 filename.c/.h:line_number
            if arg is not None and not re.match(r'^[\w/]+\.(c|h):\d+$', arg):
                return {"error": f"invalid arg: {arg}"}
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": arg}
        elif classification == "Freed":
            # 内存被释放的场景 要求的arg是函数作为参数进入某个函数的代码行
            # arg匹配 filename.c/.h:line_number
            if arg is not None and not re.match(r'^[\w/]+\.(c|h):\d+$', arg):
                return {"error": f"invalid arg: {arg}"}
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": arg}
        elif classification == "Leak":
            # 内存泄漏的场景 不需要arg
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": None}
        elif classification == "Unreachable":
            # 不可达的场景 不需要arg
            # 为指定location的return_location设置done = True
            for t_return_location in self.return_locations:
                if t_return_location["location"] == return_location:
                    t_return_location["done"] = True
                    break
            return {"classification": classification, "reason": reason, "arg": None}
        else:
            return {"error": f"unknown classification: {classification}"}
    
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

    def responseForAlter(self, alter: memory_defect.MemoryLeak):
        allowed_tools = [
            set_conclusion_desc_path,
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
        ]
        self.clear()
        malloc_loc = alter.get_source_location()
        current_function = analysis_operators.find_current_function(malloc_loc)
        self.return_locations = analysis_operators.find_return_locations(current_function["function_name"], malloc_loc)
        # [{'location': 'tif_dirread.c:4986'}, {'location': 'tif_dirread.c:4998'}, {'location': 'tif_dirread.c:5606'}, {'location': 'tif_dirread.c:5604'}]
        for return_location in self.return_locations:
            # add done = False
            return_location["done"] = False
        
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        function_prompt = f"\nYou are now working in function {current_function['function_name']}, which contains the source location of the memory allocation.\n{json.dumps(current_function, indent=4)}"
        
        return_prompt = f"For all possible return locations from source location {malloc_loc} of the function {current_function['function_name']} : \n"
        for return_location in self.return_locations:
            return_prompt += f"Return location: {return_location['location']}\n"
            return_prompt += f"Return code: {find_code_line(return_location['location'])}\n"
        return_prompt += f"You should classify the state of the variable (or the resource it holds) before the return point into one of the following six categories:\n"
        return_prompt += f"The variable is always a null pointer (NullPointer).\n"
        return_prompt += f"Ownership of the memory has been transferred (Transferred).\n"
        return_prompt += f"The memory is returned to the caller (Returned).\n"
        return_prompt += f"The memory has been freed (or 'released') before returning (Freed).\n"
        return_prompt += f"A memory leak has occurred (Leak).\n"
        return_prompt += f"This return point is unreachable (Unreachable).\n"
        
        messages = [
            {"role": "system", "content": VALUE_PATH_PROMPT + project_prompt},
            {"role": "user", "content":  f"You are tracing value flow of {extract_lhs_variable(find_code_line(malloc_loc))} at {malloc_loc} : {find_code_line(malloc_loc)}" + function_prompt + return_prompt}
        ]   
        self.analysis_logger.info(f"SYS prompt: {VALUE_PATH_PROMPT + project_prompt}")
        self.analysis_logger.info(f"USER prompt: {f"You are tracing value flow of {extract_lhs_variable(find_code_line(malloc_loc))} at {malloc_loc} : {find_code_line(malloc_loc)}" + function_prompt + return_prompt}")
        self.result_logger.info(f"USER prompt: {f"You are tracing value flow of {extract_lhs_variable(find_code_line(malloc_loc))} at {malloc_loc} : {find_code_line(malloc_loc)}" + function_prompt + return_prompt}")
        
        response = self.send_message(messages, allowed_tools)
        if not response.content: 
            response.content = ""
        self.analysis_logger.info(f"Model response: {response.content}")
        messages.append(response)
        
        # 现在应该检查是否全部的return_locations都完成了
        while not self.check_all_return_locations_done():
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                    function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                    messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
                    continue
                if tool_function_name in self.tool_method_map:
                    tool_method = self.tool_method_map[tool_function_name]
                    function_response = tool_method(**tool_arguments) if tool_arguments else tool_method()
                else:
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                self.analysis_logger.info(f"Tool response: {function_response}")
                messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
                
            response = self.send_message(messages, allowed_tools)
            if not response.content: 
                response.content = ""
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)
        
        return self.return_locations
    
    
class DeepSeekPathAnalyzer(PathAnalyzerModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        
class QwenPathAnalyzer(PathAnalyzerModel):
    def __init__(self, model_name="qwen3-max"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("QWEN_API_KEY"),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )

    
if __name__ == "__main__":
    print(analysis_operators.find_return_locations("TIFFFetchNormalTag", "tif_dirread.c:4981"))
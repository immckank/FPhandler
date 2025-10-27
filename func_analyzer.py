# 模型不擅长进行多次跨函数的跳转 要随时提醒模型
# 现在的策略是让模型沿着函数调用图来执行值流追踪
import json
import os
import logging

import analysis_operators

from config import *
from utils import *
from prompts import *
from call_graph import *
from alter_handler import AlterAnalyzer
from tools import (
    check_source_line_desc_function,
    check_source_snippet_desc_function,
    call_function_desc_function,
    return_function_desc_function,
    check_current_function_desc_function,
    check_call_stack_desc_function,
    get_back_to_initial_function_desc_function,
    jump_to_function_desc_function,
    set_conclusion_desc_function
)
import re

from abc import ABC, abstractmethod
from openai import OpenAI
import memory_defect


class FunctionAnalysisModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis") 
        self.result_logger = setup_logger(log_type="result")
        self.call_stack = []
        self.call_sites_worklist = []
        self.initial_function = None
        self.call_graph = None
        self.tool_method_map = {
            "set_conclusion": self.set_conclusion_Tool,
            "check_source_line": self.check_source_line_Tool,
            "check_source_snippet": self.check_source_snippet_Tool,
            "call_function": self.call_function_Tool,
            "return_function": self.return_function_Tool,
            "check_current_function": self.check_current_function_Tool,
            "get_back_to_initial_function": self.get_back_to_initial_function_Tool,
            "jump_to_function": self.jump_to_function_Tool,
            "check_call_stack": self.check_call_stack_Tool
        }
        
    def send_message(self, messages, tools=""):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        return response.choices[0].message  

    def clear(self):
        self.call_stack = []
        self.call_sites_worklist = []
        self.initial_function = None
        self.call_graph = CallGraph()


    def check_call_stack_Tool(self):
        current_function_info = self.call_stack[-1]
        res_str = "You are now working in function " + current_function_info["function_name"] + "\n"
        res_str += "The Call Chain is:"
        for function_info in self.call_stack:
            res_str += f"{function_info['function_name']} -> "
        res_str += "\n"
        return res_str
    
    def check_source_line_Tool(self, file_name, line_number):
        # print(f"successfully called tool with args: {file_name}, {line_number}")
        source_line_str = analysis_operators.dump_source_line(file_name, line_number)
        # 判断是否在请求当前函数内的行
        if file_name == self.call_stack[-1]["filename"] and line_number >= self.call_stack[-1]["start_line"] and line_number <= self.call_stack[-1]["end_line"]:
            return "target line:\n" + source_line_str + "\nis inside current function " + self.call_stack[-1]["function_name"] + "\n"
        else:
            return "target line:\n" + source_line_str + "\nis not inside current function " + self.call_stack[-1]["function_name"] + "\n"
    
    def check_source_snippet_Tool(self, file_name, start_line, end_line):
        # 检查片段是不是在当前函数内部
        if file_name == self.call_stack[-1]["filename"] and start_line >= self.call_stack[-1]["start_line"] and end_line <= self.call_stack[-1]["end_line"]:
            return f"target snippet from line {start_line} to line {end_line}:\n" + analysis_operators.dump_source_snippet(file_name, start_line, end_line) + "\nis inside current function " + self.call_stack[-1]["function_name"] + "\n"
        # 如果完全没有交集 提醒模型当前所在函数相关信息
        if file_name != self.call_stack[-1]["filename"]:
            return f"You are now in file {self.call_stack[-1]["filename"]} and function {self.call_stack[-1]['function_name']} from line {self.call_stack[-1]['start_line']} to line {self.call_stack[-1]['end_line']}, please use correct file name.\n"
        if start_line > self.call_stack[-1]["start_line"] or end_line < self.call_stack[-1]["end_line"]:
            return f"You are now in function {self.call_stack[-1]['function_name']} from line {self.call_stack[-1]['start_line']} to line {self.call_stack[-1]['end_line']}, please check line number.\n"
        # 有交集曾返回如下信息
        return f"some lines are not in current function, get snippet from line {max(start_line, self.call_stack[-1]['start_line'])} to line {min(end_line, self.call_stack[-1]['end_line'])}:\n" + analysis_operators.dump_source_snippet(file_name, min(start_line, self.call_stack[-1]['start_line']), max(end_line, self.call_stack[-1]['end_line']))

    def check_current_function_Tool(self):
        function_info = self.call_stack[-1]
        return "You are now working in function " + function_info["function_name"] + "\n" + json.dumps(function_info, indent=4) + "\n"

    def call_function_Tool(self, function_name, line_number):
        current_function_name = self.call_stack[-1]["function_name"]
        valid_function_name_list = analysis_operators.find_all_callees(current_function_name)
        if function_name in valid_function_name_list:
            # 检查line_number这一行的代码是否包含目标函数名
            call_line = analysis_operators.dump_source_line(self.call_stack[-1]["filename"], line_number)
            if function_name not in call_line:
                return f"failed to call function {function_name} at line {line_number}, please check your line number."
            callee_function = analysis_operators.find_function_body(function_name)
            # 为当前函数添加一个字段“called info”
            self.call_stack[-1]["called_info"] = f"You called function {function_name} at line {line_number} : {call_line}, you should continue analysis from this line."
            self.call_graph.create_call(self.call_stack[-1], callee_function, line_number)
            self.call_stack.append(callee_function)  
            for call_site in self.call_sites_worklist:
                if call_site["function_name"] == function_name:
                    call_site["done"] = True
            return "You are now working in function " + function_name + "\n" + json.dumps(callee_function, indent=4) + "\n"
        else:
            return "failed to call function " + function_name + "\n" + "the function is not a callee of " + current_function_name + "\n"

    def return_function_Tool(self):
        if len(self.call_stack) > 1:
            self.call_stack.pop()
            return f"You are now working in function {self.call_stack[-1]["function_name"]}\n The function is from lien {self.call_stack[-1]['start_line']} to line {self.call_stack[-1]['end_line']}.\n {self.call_stack[-1]['called_info']} \n"
        else:
            # 需要检查所有调用当前函数的位置？
            res_str = f"Here are all call sites of {self.call_stack[-1]['function_name']}. You should check them one by one.\n"
            call_sites = analysis_operators.find_callers(self.call_stack[-1]["function_name"])
            # [{'location': 'tif_read.c:924', 'code': '!TIFFReadBufferSetup(tif, 0, bytecountm))'}, {'location': 'tif_read.c:1335', 'code': '!TIFFReadBufferSetup(tif, 0, bytecountm))'}]
            # 找到每个调用位置所在的函数函数名
            for call_site in call_sites:
                source_location = call_site["location"]
                function_info = analysis_operators.find_current_function(source_location)
                self.call_graph.create_call(self.call_stack[-1], function_info, source_location.split(':')[1])
                call_site["function_name"] = function_info["function_name"]
                call_site["callee"] = self.call_stack[-1]["function_name"]
                call_site["done"] = False
                res_str += f"current function {self.call_stack[-1]['function_name']} is called at {call_site['location']} in function {call_site['function_name']} : {call_site['code']} \n"
                self.call_sites_worklist.append(call_site)
            return res_str
    
    def jump_to_function_Tool(self, function_name):
        # 检查 worklist 中是否存在该函数
        if not any(cs['function_name'] == function_name for cs in self.call_sites_worklist):
            return f"Error: Cannot jump to '{function_name}'. It is not in the list of pending call sites to be checked."

        self.call_stack = []
        function_info = analysis_operators.find_function_body(function_name)
        if not function_info:
            return f"Failed to jump to function {function_name}. It might not exist or there was an error finding it."
        self.call_stack.append(function_info)
        # 如果添加的这个函数名和worklist中的函数名一致 设置为done
        for call_site in self.call_sites_worklist:
            if call_site["function_name"] == function_name:
                call_site["done"] = True
        return f"You have jumped to function {function_name}.\n" + json.dumps(function_info, indent=4)

    def get_back_to_initial_function_Tool(self):
        # 如果initial function就在调用栈顶
        if self.initial_function["function_name"] == self.call_stack[-1]["function_name"]:
            return "You are already at the initial function.\n" + self.check_call_stack_Tool()
        # 如果initial function被包含在调用栈内 & 不是栈顶
        if self.initial_function["function_name"] in [cs["function_name"] for cs in self.call_stack]:
            return "You should return to the initial function since initial function is already in your call stack.\n" + self.check_call_stack_Tool()
        self.call_stack = []
        self.call_stack.append(self.initial_function)
        for call_site in self.call_sites_worklist:
            if call_site["function_name"] == self.initial_function["function_name"]:
                call_site["done"] = True
        return "You are now working in function triggers alter " + self.initial_function["function_name"] + "\n" + json.dumps(self.initial_function, indent=4) + "\n"

    def set_conclusion_Tool(self, classification, reason):
        res_str = "You should check all the function call sites first.\n"
        permission = True
        if self.initial_function["function_name"] in [cs["function_name"] for cs in self.call_stack] and self.initial_function["function_name"] != self.call_stack[-1]["function_name"]:
            return "You should check along the return path to the initial function to come to a conclusion.\n" + self.check_call_stack_Tool()
        for call_site in self.call_sites_worklist:
            if not call_site["done"]:
                res_str += f"function {call_site['function_name']} called {call_site['callee']} at {call_site['location']} : {call_site['code']} has not done yet\n"
                permission = False
        if not permission:
            return res_str + "You can jump to one of the unfinished call sites using the 'jump_to_function' tool to finish your analysis.\n"
        else:
            return analysis_operators.set_conclusion(classification, reason)

    def responseForAlter(self, alter : memory_defect.MemoryLeak):
        allowed_tools = [
            set_conclusion_desc_function, check_source_line_desc_function, check_source_snippet_desc_function, 
            check_current_function_desc_function, call_function_desc_function, return_function_desc_function,
            get_back_to_initial_function_desc_function, check_call_stack_desc_function
        ]
        self.clear()
        malloc_loc = alter.get_source_location()
        current_function = analysis_operators.find_current_function(malloc_loc)
        self.call_stack.append(current_function)
        self.initial_function = current_function
        self.call_graph.create_node(current_function)
        
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        function_prompt = f"You are now working in function {self.call_stack[-1]['function_name']}, which contains the source location of the alert.\n{json.dumps(self.call_stack[-1], indent=4)}"
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT + FUNCTION_PROMPT},
            {"role": "user", "content": project_prompt + alter.to_prompt() + function_prompt}
        ]   
        self.analysis_logger.info(f"SYS prompt: {SYS_PROMPT + ASSUMPTION_PROMPT + FUNCTION_PROMPT}")
        self.analysis_logger.info(f"USER prompt: {project_prompt + alter.to_prompt() + function_prompt}")
        self.result_logger.info(f"\nUSER prompt: {alter.to_prompt()}\n")
        
        # 初始化第一次对话
        response = self.send_message(messages, allowed_tools)
        if not response.content: 
            response.content = ""
        self.analysis_logger.info(f"Model response: {response.content}")
        messages.append(response)
        
        # 处理工具调用的循环
        while True:
            # 如果没有工具调用，退出循环
            if not response.tool_calls:
                break
                
            # 处理每个工具调用
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                
                # 解析工具参数
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                    function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                    messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
                    continue
                    
                self.analysis_logger.info(f"Tool call: {tool_function_name} with arguments: {tool_arguments}")
                
                # 执行工具调用
                if tool_function_name in self.tool_method_map:
                    tool_method = self.tool_method_map[tool_function_name]
                    function_response = tool_method(**tool_arguments) if tool_arguments else tool_method()
                    
                    # 特殊处理set_conclusion工具的响应
                    if tool_function_name == "set_conclusion":
                        if "error" in function_response:
                            pass
                        elif not "classification" in function_response or not "reason" in function_response:
                            # 返回的不是json格式 字段classification reason
                            pass
                        else:
                            self.analysis_logger.info(f"Tool response: {function_response}")
                            self.result_logger.info(f"{function_response}")
                            return
                else:
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
                    
                # 格式化响应并添加到消息列表
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                self.analysis_logger.info(f"Tool response: {function_response}")
                messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
            
            # 更新允许的工具列表
            if any(not call_site['done'] for call_site in self.call_sites_worklist):
                if jump_to_function_desc_function not in allowed_tools:
                    allowed_tools.append(jump_to_function_desc_function)
            else:
                if jump_to_function_desc_function in allowed_tools:
                    allowed_tools.remove(jump_to_function_desc_function)
            
            # 获取下一轮响应
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)
        
        return

class DeepSeekFunctionAnalyzer(FunctionAnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        
class QwenFunctionAnalyzer(FunctionAnalysisModel):
    def __init__(self, model_name="qwen3-max"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("QWEN_API_KEY"),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        ) 
    
    def conclusion_xml_handling(self, response_content):
        # 识别模式<>
        pattern = r"<function=(.*?)>\s*<parameter=classification>\s*(.*?)\s*</parameter>\s*<parameter=reason>\s*(.*?)\s*</parameter>\s*</function>"
        match = re.search(pattern, response_content, re.DOTALL)
        if match:
            classification = match.group(2)
            reason = match.group(3)
            return {"classification": classification, "reason": reason}
        return None

    def responseForAlter(self, alter : memory_defect.MemoryLeak):
        allowed_tools = [
            set_conclusion_desc_function, check_source_line_desc_function, check_source_snippet_desc_function, 
            check_current_function_desc_function, call_function_desc_function, return_function_desc_function,
            get_back_to_initial_function_desc_function, check_call_stack_desc_function
        ]
        self.clear()
        malloc_loc = alter.get_source_location()
        print(f"malloc_loc: {malloc_loc}")
        current_function = analysis_operators.find_current_function(malloc_loc)
        print(f"current_function: {current_function}")
        self.call_stack.append(current_function)
        self.initial_function = current_function
        self.call_graph.create_node(current_function)
        
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        function_prompt = f"You are now working in function {self.call_stack[-1]['function_name']}, which contains the source location of the alert.\n{json.dumps(self.call_stack[-1], indent=4)}"
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT + FUNCTION_PROMPT},
            {"role": "user", "content": project_prompt + alter.to_prompt() + function_prompt}
        ]   
        self.analysis_logger.info(f"SYS prompt: {SYS_PROMPT + ASSUMPTION_PROMPT + FUNCTION_PROMPT}")
        self.analysis_logger.info(f"USER prompt: {project_prompt + alter.to_prompt() + function_prompt}")
        self.result_logger.info(f"\nUSER prompt: {alter.to_prompt()}\n")
        
        # 初始化第一次对话
        response = self.send_message(messages, allowed_tools)
        if not response.content: 
            response.content = ""
        self.analysis_logger.info(f"Model response: {response.content}")
        messages.append(response)
        
        # 处理工具调用的循环
        while True:
            # 如果没有工具调用，退出循环
            if not response.tool_calls:
                break
                
            # 处理每个工具调用
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                
                # 解析工具参数
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                    function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                    messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
                    continue
                    
                self.analysis_logger.info(f"Tool call: {tool_function_name} with arguments: {tool_arguments}")
                
                # 执行工具调用
                if tool_function_name in self.tool_method_map:
                    tool_method = self.tool_method_map[tool_function_name]
                    function_response = tool_method(**tool_arguments) if tool_arguments else tool_method()
                    
                    # 特殊处理set_conclusion工具的响应
                    if tool_function_name == "set_conclusion":
                        if "error" in function_response:
                            pass
                        elif not "classification" in function_response or not "reason" in function_response:
                            # 返回的不是json格式 字段classification reason
                            pass
                        else:
                            self.analysis_logger.info(f"Tool response: {function_response}")
                            self.result_logger.info(f"{function_response}")
                            return
                else:
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
                    
                # 格式化响应并添加到消息列表
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                self.analysis_logger.info(f"Tool response: {function_response}")
                messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
            
            # 更新允许的工具列表
            if any(not call_site['done'] for call_site in self.call_sites_worklist):
                if jump_to_function_desc_function not in allowed_tools:
                    allowed_tools.append(jump_to_function_desc_function)
            else:
                if jump_to_function_desc_function in allowed_tools:
                    allowed_tools.remove(jump_to_function_desc_function)
            
            # 获取下一轮响应
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            conclusion = self.conclusion_xml_handling(response.content)
            if conclusion:
                # 表明模型尝试使用set_conclusion工具
                # {"classification": classification, "reason": reason} 以这个参数尝试调用set_conclusion工具
                classification = conclusion["classification"]
                reason = conclusion["reason"]
                function_response = self.set_conclusion_Tool(classification, reason)
                if "error" in function_response or not "classification" in function_response or not "reason" in function_response:
                    # 组装工具返回给模型
                    self.analysis_logger.info(f"Tool response: {function_response}")
                    messages.append({ "role": "user", "content": f"You should use tool set conclusion and an error occurred: {function_response}" })
                else:
                    # 模型实际上已经成功给出结论了
                    self.analysis_logger.info(f"Tool response: {function_response}")
                    self.result_logger.info(f"conclusion with xml: {function_response}")
                    break
            else:
                self.analysis_logger.info(f"Model response: {response.content}")
                messages.append(response)
        
        return 

if __name__ == "__main__":
    # TIFFFillStrip
    print(analysis_operators.find_function_body("TIFFFillStrip"))
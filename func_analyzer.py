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
    
    @abstractmethod
    def responseToAlter(self, alter_prompt, user_prompt=""):
        pass
    
    @abstractmethod
    def responseForAlter(self, alter_prompt, user_prompt=""):
        pass

class DeepSeekFunctionAnalyzer(FunctionAnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
    
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
    
    def ret_function_Tool(self):
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
        res_str = "You should check all the function call sites first."
        permission = True
        if self.initial_function["function_name"] in [cs["function_name"] for cs in self.call_stack] and self.initial_function["function_name"] != self.call_stack[-1]["function_name"]:
            return "You should check along the return path to the initial function to come to a conclusion.\n" + self.check_call_stack_Tool()
        for call_site in self.call_sites_worklist:
            if not call_site["done"]:
                res_str += f"function {call_site['function_name']} called {call_site['callee']} at {call_site['location']} : {call_site['code']} has not done yet\n"
                permission = False
        if not permission:
            return res_str
        else:
            return analysis_operators.set_conclusion(classification, reason)

    def send_message(self, messages, tools=""):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        return response.choices[0].message  

    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter : memory_defect.MemoryLeak):
        allowed_tools = []
        # set conclusion
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
        # check source line
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "check_source_line",
                "description": "Dumps a single line of source code from a file and check whether it is in the current function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                        "line_number": {"type": "integer", "description": "The line number of the source code."}
                    },
                    "required": ["file_name", "line_number"]
                }
            }
        })
        # check source snippet
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "check_source_snippet",
                "description": "Dumps code snippet of source code inside current function from a file between the given line numbers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                        "start_line": {"type": "integer", "description": "The starting line number of the snippet."},
                        "end_line": {"type": "integer", "description": "The ending line number of the snippet."}
                    },
                    "required": ["file_name", "start_line", "end_line"]
                }
            }
        })
        # call function
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "call_function",
                "description": "Get to work in a new function called by the current function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string", "description": "The name of the function to call."},
                        "line_number": {"type": "integer", "description": "The line number where the function is called."}
                    },
                    "required": ["function_name", "line_number"]
                }
            }
        })
        # ret 
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "ret",
                "description": "Return to the caller of the current function. If the current function is the initial function of the analysis, this action will find all its call sites to create a worklist for further investigation.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
        # check current function
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "check_current_function",
                "description": "Check the current function name and function body in source code.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }                
            }
        })
        # check call stack
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "check_call_stack",
                "description": "Check your call chain to the current function.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }  
            }
        })                
        # get back to initial function
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "get_back_to_initial_function",
                "description": "Get back to the initial function of the analysis.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                } 
            }
        })
        
        jump_tool = {
            "type": "function",
            "function": {
                "name": "jump_to_function",
                "description": "Jump to a specific function from the call site worklist to continue the analysis there. This is used after returning from the initial function to investigate its callers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string", 
                            "description": "The name of the function to jump to. Must be one of the functions from the call site worklist that has not been marked as 'done'."
                        }
                    },
                    "required": ["function_name"]
                }
            }
        }

        # 模型应该从变量创建的函数出发
        # case 在当前函数内被free 只需要分析当前函数内的分支跳转等就可以
        # case 在其他函数内被free 让模型沿着调用图向图深处发生call 在某个子位置发生了free
        # case 作为返回值传递给了调用者后 由外部函数free 要找到所有callsites 是不是都进行负责了free
        # 数据结构 调用栈 栈顶是current 
        # 调用栈存func info信息 
        # filename function_name start_line end_line function_body

        malloc_loc = alter.get_source_location()
        current_function = analysis_operators.find_current_function(malloc_loc)
        self.call_stack = []
        self.call_stack.append(current_function)
        self.initial_function = current_function
        self.call_sites_worklist = []
        self.call_graph = CallGraph()
        self.call_graph.create_node(current_function)
        
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        function_prompt = f"You are now working in function {self.call_stack[-1]['function_name']}, which contains the source location of the alert.\n{json.dumps(self.call_stack[-1], indent=4)}"
        messages = [
            {"role": "system", "content": SYS_PROMPT+ASSUMPTION_PROMPT},
            {"role": "user", "content": project_prompt + alter.to_prompt() + function_prompt}
        ]   
        self.analysis_logger.info(f"SYS prompt: {SYS_PROMPT+ASSUMPTION_PROMPT}")
        self.analysis_logger.info(f"USER prompt: {project_prompt + alter.to_prompt() + function_prompt}")
        self.result_logger.info(f"\nUSER prompt: {alter.to_prompt()}\n")
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
                self.analysis_logger.info(f"Tool call: {tool_function_name} with arguments: {tool_arguments}")
                if tool_function_name == "set_conclusion":
                    function_response = self.set_conclusion_Tool(**tool_arguments)
                    if "error" in function_response:
                        pass
                    elif not "classification" in function_response or not "reason" in function_response:
                        # 返回的不是json格式 字段classification reason
                        pass
                    else:
                        self.analysis_logger.info(f"Tool response: {function_response}")
                        self.result_logger.info(f"{function_response}")
                        return
                elif tool_function_name == "check_source_line":
                    function_response = self.check_source_line_Tool(**tool_arguments)
                elif tool_function_name == "check_source_snippet":
                    function_response = self.check_source_snippet_Tool(**tool_arguments)
                elif tool_function_name == "call_function":
                    function_response = self.call_function_Tool(**tool_arguments)
                elif tool_function_name == "ret":
                    function_response = self.ret_function_Tool()
                elif tool_function_name == "check_current_function":
                    function_response = self.check_current_function_Tool()
                elif tool_function_name == "get_back_to_initial_function":
                    function_response = self.get_back_to_initial_function_Tool()
                elif tool_function_name == "jump_to_function":
                    function_response = self.jump_to_function_Tool(**tool_arguments)
                elif tool_function_name == "check_call_stack":
                    function_response = self.check_call_stack_Tool()
                else:
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
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
            # 如果有未完成!done的call sites list 
            #   允许模型使用工具jump_to_function
            # 如果没有 检查有没有工具jump_to_function 有则删除
            if any(not call_site['done'] for call_site in self.call_sites_worklist):
                if jump_tool not in allowed_tools:
                    allowed_tools.append(jump_tool)
            else:
                if jump_tool in allowed_tools:
                    allowed_tools.remove(jump_tool)
            response = self.send_message(messages, allowed_tools)
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)
        
        # 在一个函数内模型需要的工具
        # check line(line num) 函数内 函数外两套说明
        # check value flow in func(varname/loc)
        # check global() 告诉模型所有全局变量/对象名？这个能实现吗

        # 函数调用
        # call func(func name) 检查当前函数是不是能调用所给的函数名
        # 若能 告知模型跳转到新的函数内部工作
        # 若不能 告知模型依然在当前函数 仅提供模型需要的函数的展示信息

        # 函数返回
        # ret func() 检查当前调用栈内的信息
        # 如果超过1个 弹出栈顶 更新新的目前的函数信息 告诉模型
        # 如果只有1个 告诉模型所有当前函数的caller 再进行一次特殊对话使用工具ret to func(func name)

        # 回到最一开始的函数位置
        # reset func() 同时会重置调用栈
        
if __name__ == "__main__":
    # TIFFFillStrip
    print(analysis_operators.find_function_body("TIFFFillStrip"))
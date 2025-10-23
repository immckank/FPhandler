# 模型不擅长进行多次跨函数的跳转 要随时提醒模型
# 现在的策略是让模型沿着函数调用图来执行值流追踪
import json
import os
import logging

import analysis_operators

from config import *
from utils import *
from prompts import *
from alter_handler import AlterAnalyzer
import re

from openai import OpenAI
import memory_defect



class FunctionAnalysisModel():
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis") 
        self.result_logger = setup_logger(log_type="result")
        self.call_stack = []
        self.call_sites_worklist = []
        self.initial_function = None
    
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter_prompt, user_prompt=""):
        return None

class DeepSeekFunctionAnalyzer(FunctionAnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
    
    def check_source_line_Tool(self, file_name, line_number):
        # print(f"successfully called tool with args: {file_name}, {line_number}")
        source_line_str = analysis_operators.dump_source_line(file_name, line_number)
        # 判断是否在请求当前函数内的行
        if file_name == self.call_stack[-1]["filename"] and line_number >= self.call_stack[-1]["start_line"] and line_number <= self.call_stack[-1]["end_line"]:
            return "target line:\n" + source_line_str + "\nis inside current function " + self.call_stack[-1]["function_name"] + "\n"
        else:
            return "target line:\n" + source_line_str + "\nis not inside current function " + self.call_stack[-1]["function_name"] + "\n"
    
    def check_current_function_Tool(self):
        function_info = self.call_stack[-1]
        return "You are now working in function " + function_info["function_name"] + "\n" + json.dumps(function_info, indent=4) + "\n"

    def call_function_Tool(self, function_name):
        current_function_name = self.call_stack[-1]["function_name"]
        valid_function_name_list = analysis_operators.find_all_callees(current_function_name)
        if function_name in valid_function_name_list:
            callee_function = analysis_operators.find_function_body(function_name)
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
            return "You are now working in function " + self.call_stack[-1]["function_name"] + "\n" + json.dumps(self.call_stack[-1], indent=4) + "\n"
        else:
            # 需要检查所有调用当前函数的位置？
            res_str = f"Here are all call sites of {self.call_stack[-1]['function_name']}. You should check them one by one.\n"
            call_sites = analysis_operators.find_callers(self.call_stack[-1]["function_name"])
            # [{'location': 'tif_read.c:924', 'code': '!TIFFReadBufferSetup(tif, 0, bytecountm))'}, {'location': 'tif_read.c:1335', 'code': '!TIFFReadBufferSetup(tif, 0, bytecountm))'}]
            # 找到每个调用位置所在的函数函数名
            for call_site in call_sites:
                source_location = call_site["location"]
                function_info = analysis_operators.find_current_function(source_location)
                call_site["function_name"] = function_info["function_name"]
                call_site["callee"] = self.call_stack[-1]["function_name"]
                call_site["done"] = False
                res_str += f"current function {self.call_stack[-1]['function_name']} is called at {call_site['location']} in function {call_site['function_name']} : {call_site['code']} \n"
                self.call_sites_worklist.append(call_site)
            return res_str
    
    def jump_to_function_Tool(self, function_name):
        self.call_stack = []
        self.call_stack.append(analysis_operators.find_function_body(function_name))
        # 如果添加的这个函数名和worklist中的函数名一致 设置为done
        for call_site in self.call_sites_worklist:
            if call_site["function_name"] == function_name:
                call_site["done"] = True

    def get_back_to_initial_function_Tool(self):
        self.call_stack = []
        self.call_stack.append(self.initial_function)
        for call_site in self.call_sites_worklist:
            if call_site["function_name"] == self.initial_function["function_name"]:
                call_site["done"] = True

    def set_conclusion_Tool(self, classification, reason):
        res_str = "You should check all the function call sites first."
        permission = True
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
        # call function
        allowed_tools.append({
            "type": "function",
            "function": {
                "name": "call_function",
                "description": "Get to work in a new function called by the current function.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string", "description": "The name of the function to call."}
                    },
                    "required": ["function_name"]
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

        # 模型应该从变量创建的函数出发
        # case 在当前函数内被free 只需要分析当前函数内的分支跳转等就可以
        # case 在其他函数内被free 让模型沿着调用图向图深处发生call 在某个子位置发生了free
        # case 作为返回值传递给了调用者后 由外部函数free 要找到所有callsites 是不是都进行负责了free
        # 数据结构 调用栈 栈顶是current 
        # 调用栈存func info信息 
        # filename function_name start_line end_line function_body

        malloc_loc = alter.get_source_location()
        current_function = analysis_operators.find_current_function(malloc_loc)
        self.call_stack.append(current_function)
        self.initial_function = current_function
        
        # 第一次对话 告诉模型任务 
        # 告知当前所在函数信息
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        function_prompt = f"You are now working in function {self.call_stack[-1]['function_name']}, which contains the source location of the alert.\n{json.dumps(self.call_stack[-1], indent=4)}"
        messages = [
            {"role": "system", "content": SYS_PROMPT+ASSUMPTION_PROMPT},
            {"role": "user", "content": project_prompt + alter.to_prompt() + function_prompt}
        ]   
        response = self.send_message(messages, allowed_tools)
        print(response)  
        messages.append(response)
        while response.tool_calls:
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    # Log and respond with an error so the model can recover
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
                if tool_function_name == "set_conclusion":
                    function_response = self.set_conclusion_Tool(**tool_arguments)
                    if "error" in function_response:
                        continue
                    else:
                        print(function_response)
                        return
                if tool_function_name == "check_source_line":
                    function_response = self.check_source_line_Tool(**tool_arguments)
                elif tool_function_name == "call_function":
                    function_response = self.call_function_Tool(**tool_arguments)
                elif tool_function_name == "ret":
                    function_response = self.ret_function_Tool()
                elif tool_function_name == "check_current_function":
                    function_response = self.check_current_function_Tool()
                else:
                    function_response = f"Error: Tool '{tool_function_name}' not found."

                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                print(function_response)
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "content": function_response,
                })
            response = self.send_message(messages, allowed_tools)
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
    analyzer = DeepSeekFunctionAnalyzer()
    handler = AlterAnalyzer()
    handler.read_alter_file(SAR_ROOT_PATH, sar_name)
    alter_example = handler.get_alter_list()[0]
    analyzer.responseForAlter(alter_example)
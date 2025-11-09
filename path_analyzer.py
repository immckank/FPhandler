# 更进一步的细化模型的任务 制作小部分的工作-》说明到一个ret位置 值对象状态如何

import os
import json
import logging
import copy
from tracemalloc import start

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
    create_path_desc_path,
    add_path_gep_to_baseobj_desc_path,
    add_path_gep_to_member_desc_path,
    complete_path_desc_path,
    query_paths_desc_path,
    delete_path_desc_path
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
        self.tool_method_map = {
            "create_path": self.create_path_Tool,
            "add_path_gep_to_baseobj": self.add_path_gep_to_baseobj_Tool,
            "add_path_gep_to_member": self.add_path_gep_to_member_Tool,
            "complete_path": self.complete_path_Tool,
            "query_paths": self.query_paths_Tool,
            "delete_path": self.delete_path_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
        }
        self.global_variables = []
        self.memcached = []
        self.alter_prompt = ""
        self.tmp_path_list = []
        self.l_return_locations = []

    def send_message(self, messages, tools=""):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        return response.choices[0].message  
    
    def check_return_location_completeness(self):
        # 找出所有未完成的return location
        # 实现有问题？
        incomplete_return_locations = []
        for l_return_location in self.l_return_locations:
            visited = False
            for path in self.tmp_path_list:
                if path["return_location"] == l_return_location and path["status"] == "completed":
                    visited = True
                    break
            if not visited:
                incomplete_return_locations.append(l_return_location)
        if len(incomplete_return_locations) > 0:
            return {"error": f"The return locations {incomplete_return_locations} are not complete.", "success": False}
        return {"success": True}
    
    def check_path_completeness(self):
        incomplete_paths = []
        for path in self.tmp_path_list:
            if path["status"] == "active":
                incomplete_paths.append(path["path_id"])
        if len(incomplete_paths) > 0:
            return {"error": f"The paths {incomplete_paths} are not complete.", "success": False}
        return {"success": True}

    def create_path_Tool(self, return_location, description, path_id):
        path_id = str(path_id)
        new_path = {
            "path_id": path_id,
            "return_location": return_location,
            "status": "active",
            "path_items": [],
            "description": description
        }
        self.tmp_path_list.append(new_path)
        return new_path

    def add_path_gep_to_baseobj_Tool(self, path_id, gep_location, baseobj_name, basic_info):
        gep_to_baseobj_path_item = {
            "value_object": basic_info["value_object"],
            "function_name": basic_info["function_name"],
            "classification": "GEP to baseobj",
            "source_location": gep_location,
            "baseobj_name": baseobj_name
        }
        # 在self.tmp_path_list中找到path_id对应的path 并添加gep_to_baseobj_path_item
        # 用lamda表达式找到path_id对应的path
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id, self.tmp_path_list))
        path["path_items"].append(gep_to_baseobj_path_item)
        return gep_to_baseobj_path_item

    def add_path_gep_to_member_Tool(self, path_id, gep_location, member_name, basic_info):
        gep_to_member_path_item = {
            "value_object": basic_info["value_object"],
            "function_name": basic_info["function_name"],
            "classification": "GEP to member",
            "source_location": gep_location,
            "member_name": member_name
        }
        # 在self.tmp_path_list中找到path_id对应的path 并添加gep_to_member_path_item
        # 用lamda表达式找到path_id对应的path
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id, self.tmp_path_list))
        path["path_items"].append(gep_to_member_path_item)
        return gep_to_member_path_item

    def query_paths_Tool(self, path_id):
        # 暂时过滤掉deleted的path
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id and x["status"] != "deleted", self.tmp_path_list), None)
        if path is None:
            return {"error": f"path_id {path_id} not found or deleted."}
        return path

    def delete_path_Tool(self, path_id):
        path_id = str(path_id)
        self.tmp_path_list = list(filter(lambda x: x["path_id"] != path_id, self.tmp_path_list))
        return {"path_id": path_id, "status": "deleted"}

    def complete_path_Tool(self, path_id, classification, reason, source_location=None, code_line=None, arg=None, basic_info={}):
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id, self.tmp_path_list), None)
        if path is None:
            return {"error": f"path_id {path_id} not found."}
        if path["status"] == "deleted":
            return {"error": f"path_id {path_id} is deleted."}
        if path["status"] == "completed":
            return {"error": f"path_id {path_id} is completed."}
        return_location = path["return_location"]

        if classification == "NullPointer":
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            })
            path["status"] = "completed"
            return path
        elif classification == "Transferred with assignment":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Transferred with assignment classification"}
            if arg is None:
                return {"error": f"arg is required for Transferred with assignment classification to specify which variable the memory was transferred to."}
            eq_position_l = analysis_operators.get_eq_position_list(source_location)
            if eq_position_l is None:
                return {"error": f"The code line at {source_location} : {find_code_line(source_location)} has no related store statement. Please check if the code line is correct."}
            matched_arg = False
            # TODO 可以再增加函数右边必须包含当前追踪的变量名
            for eq_position in eq_position_l:
                code_line = find_code_line(source_location)
                if arg in code_line[:eq_position]:
                    matched_arg = True
                    break
            if not matched_arg:
                return {"error": f"Cannot find varname: {arg} in the code line at {source_location} : {find_code_line(source_location)}. Please check if the code line is correct or the arg is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            })
            path["status"] = "completed"
            return path
        elif classification == "Returned to caller":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Returned classification"}
            return_pointer_json = analysis_operators.check_return_pointer(return_location)
            if not return_pointer_json["function_can_return_pointer"] or not return_pointer_json["location_has_pointer_operation"]:
                return {"error": f"the function {basic_info['function_name']} at {source_location} cannot return a pointer, or the return location {return_location} does not have pointer operation. Do you mean the memory is transferred?"}
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            })
            path["status"] = "completed"
            return path
        elif classification == "Handled by callee":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Handled by callee classification"}
            if arg is None:
                return {"error": f"arg is required for Handled by callee classification to specify which function was used to release the memory."}
            path_items = path["path_items"]
            if len(path_items) == 0:
                # 需要设计几个backup valuename 可以允许没有& 增添& 没有* 增添*
                extracted_function_name, arg_index = get_arg_index(code_line, basic_info["value_object"])
                if extracted_function_name is None or arg_index is None:
                    return {"error": f"Cannot find the function name and arg index in the code line at {source_location} : {find_code_line(source_location)} for the arg {basic_info['value_object']}. You may just give the code line where the transfer happens or check if the code line is correct or the arg is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                elif extracted_function_name != arg:
                    return {"error": f"The function name {extracted_function_name} is not the same as the arg {arg}.Please check if the function name is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                else:
                    pass
            else:
                last_event = path_items[-1]
                if last_event["classification"] == "GEP to baseobj":
                    # 那实际上追踪的变量名就是base变量名
                    base_variable_name = last_event["baseobj_name"]
                    extracted_function_name, arg_index = get_arg_index(code_line, base_variable_name)
                    if extracted_function_name is None or arg_index is None:
                        return {"error": f"Cannot find the function name and arg index in the code line at {source_location} : {find_code_line(source_location)} for the base variable {base_variable_name}. You may just give the code line where the transfer happens or check if the code line is correct or the arg is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                    elif extracted_function_name != arg:
                        return {"error": f"The function name {extracted_function_name} is not the same as the arg {arg}.Please check if the function name is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                    else:
                        pass
                else:
                    member_variable_name = last_event["member_name"]
                    extracted_function_name, arg_index = get_arg_index(code_line, member_variable_name)
                    if extracted_function_name is None or arg_index is None:
                        return {"error": f"Cannot find the function name and arg index in the code line at {source_location} : {find_code_line(source_location)} for the member variable {member_variable_name}. You may just give the code line where the transfer happens or check if the code line is correct or the arg is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                    elif extracted_function_name != arg:
                        return {"error": f"The function name {extracted_function_name} is not the same as the arg {arg}.Please check if the function name is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
                    else:
                        pass
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            })
            path["status"] = "completed"
            return path
        elif classification == "Leak":
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            })
            path["status"] = "completed"
            return path
        elif classification == "Unreachable":
            path["path_items"].append({
                "value_object": basic_info["value_object"],
                "start_location": basic_info["start_location"],
                "function_name": basic_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            })
            path["status"] = "completed"
            return path
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
    
    def analysis_function_paths(self, start_loc, previous_analysis_path=[], current_function=None, mode={"mode" : "local variable", "arg": None}, var_name=None):
        allowed_tools = [
            create_path_desc_path,
            add_path_gep_to_baseobj_desc_path,
            add_path_gep_to_member_desc_path,
            complete_path_desc_path,
            query_paths_desc_path,
            delete_path_desc_path,
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
        ]
        return_locations = []
        path_idx = 0
        self.tmp_path_list = []
        self.l_return_locations = []
        if var_name is None:
            # 事实上所有调用位置都已经处理过了 
            if mode["mode"] == "local variable":
                var_name = extract_lhs_variable(find_code_line(start_loc))
            elif mode["mode"] == "formal argument":
                function_start_line = current_function["start_line"]
                function_start_location = f"{current_function['filename']}:{function_start_line}"
                function_start_code_line = find_code_line(function_start_location)
                var_name = get_formal_arg_names(function_start_code_line)[int(start_loc)]
            else:
                # TODO call arg
                var_name = extract_lhs_variable(find_code_line(start_loc))
        basic_info = {
            "value_object": var_name,
            "start_location": start_loc,
            "function_name": current_function["function_name"],
            "mode" : mode
        }        
        function_prompt = ""
        if mode["mode"] == "formal argument":
            arg_index = mode["arg"]
            wappered_return_locations = analysis_operators.get_value_sensitive_arg_icfg_return_path(current_function["function_name"], arg_index)
            function_prompt += f"\nYou are now tracing the memory of the {arg_index}th formal argument of the function {current_function['function_name']} at {start_loc} : {find_code_line(f"{current_function['filename']}:{current_function['start_line']}")}.\n"
        elif mode["mode"] == "local variable":
            # 定位eqposition
            eq_position = mode["arg"]
            wappered_return_locations = analysis_operators.get_value_sensitive_icfg_return_path(start_loc, eq_position)
            function_prompt += f"\nYou are now tracing the memory of the local variable {var_name} at {start_loc} : {find_code_line(start_loc)}.\n"
        elif mode["mode"] == "call argument":
            arg_index = mode["arg"]
            # 这里需要再补充一个参数为callee function name
            callee_function_name = previous_analysis_path[-1]["function_name"]
            wappered_return_locations = analysis_operators.get_value_sensitive_call_arg_icfg_return_path(start_loc, arg_index, callee_function_name)
            function_prompt += f"\nYou are now tracing the memory of the variable {var_name} used as the {arg_index}th call argument to call {callee_function_name} in the function {current_function['function_name']} at {start_loc} : {find_code_line(start_loc)}.\n"
        function_prompt += f"current function:{json.dumps(current_function, indent=4)}"
        print(f"wappered_return_locations: {wappered_return_locations}")
        for wappered_return_location in wappered_return_locations:
            return_location = {
                "location": f"{wappered_return_location["location"]["fl"]}:{wappered_return_location["location"]["ln"]}",
                "done": 0,
                "group_items": [],
                "path_count": wappered_return_location["mergeable_groups"]
            }
            if wappered_return_location["mergeable_groups"] > 1:
                for path_group in wappered_return_location["path_groups"]:
                    group_items = read_group(path_group)
                    return_location["group_items"].append(group_items)
            if return_location["path_count"] > 0:
                self.l_return_locations.append(f"{wappered_return_location["location"]["fl"]}:{wappered_return_location["location"]["ln"]}")
        project_prompt = f"You are now working for project {PROJECT_NAME}. "
        project_prompt += PROJECT_DESC + "\n"
        if previous_analysis_path:
            previous_analysis_path_prompt = "The previous analysis shows that there exists a path leads to current function as follows:\n"
            for previous_analysis_path_item in previous_analysis_path:
                previous_analysis_path_prompt += f"The memory of {previous_analysis_path_item['value_object']} at {previous_analysis_path_item['start_location']} : {find_code_line(previous_analysis_path_item['start_location'])}"
                previous_analysis_path_prompt += f"is {previous_analysis_path_item['classification']} in the function {previous_analysis_path_item['function_name']} at {previous_analysis_path_item['source_location']} : {find_code_line(previous_analysis_path_item['source_location'])} and returned at {previous_analysis_path_item['return_location']} : {find_code_line(previous_analysis_path_item['return_location'])}.\n"
                previous_analysis_path_prompt += f"with explanation that {previous_analysis_path_item['reason']}\n"
        else:
            previous_analysis_path_prompt = ""
        # return_prompt = f"For all possible return locations of the function {current_function['function_name']} : \n"
        return_prompt = f"All possible paths to the return location of the function {current_function['function_name']} are as follows:\n"
        for return_location in return_locations:
            # 还是不处理r可抵达的path为0的eturn location
            if return_location['path_count'] == 0:
                continue
            return_prompt += f"Return location: {return_location['location']} : {find_code_line(return_location['location'])}\n"
            return_prompt += f"There maybe {return_location['path_count']} possible path to the return location.\n"
            if return_location['path_count'] == 1:
                return_prompt += "The return location is reachable.\n"
                continue
            for i in range(len(return_location['group_items'])):
                return_prompt += f"Path {i}: "
                if return_location['group_items'][i]:
                    for vfg_node_item in return_location['group_items'][i]:
                        return_prompt += f"passed {vfg_node_item['vfg_node_kind']} at {vfg_node_item['location']} : {find_code_line(vfg_node_item['location'])}\n"                
                else:
                    return_prompt += "basic path\n"
        return_prompt += f"You should claim the state of the variable {var_name} (or the resource it holds) along all paths to the return point as following six categories:\n"
        return_prompt += f"The variable is always a null pointer (NullPointer).\n"
        return_prompt += f"Ownership of the memory has been transferred through an assignment to another variable (Transferred with assignment).\n"
        return_prompt += f"The memory is returned as return value to the caller (Returned to caller).\n"
        return_prompt += f"The memory will be handled by the callee (Handled by callee).\n"
        return_prompt += f"A memory leak has occurred (Leak).\n"
        return_prompt += f"This return point is unreachable (Unreachable), Or, this return point is unreachable because of conditional logic on the path.\n"
        return_prompt += "For each potential execution path, first use create_path to register it, record any struct GEP transitions with add_path_gep_to_baseobj or add_path_gep_to_member, and finalize the judgement with complete_path once you determine the classification. You may query or delete paths using query_paths and delete_path if necessary.\n"
        messages = [
            {"role": "system", "content": VALUE_PATH_PROMPT + project_prompt},
            {"role": "user", "content": self.alter_prompt + previous_analysis_path_prompt +function_prompt + return_prompt}
        ]   
        self.analysis_logger.info(f"SYS prompt: {VALUE_PATH_PROMPT + project_prompt}")
        self.analysis_logger.info(f"USER prompt: {self.alter_prompt + previous_analysis_path_prompt + function_prompt + return_prompt}")
        self.result_logger.info(f"USER prompt: {self.alter_prompt + previous_analysis_path_prompt + function_prompt + return_prompt}")
        
        try:
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            self.analysis_logger.info(f"Model response: {response.content}")
            messages.append(response)

            while True:
                if not response.tool_calls:
                    if self.check_path_completeness()["success"]:
                        break
                    error_messgae = ""
                    # if not self.check_return_location_completeness()["success"]:
                    #     error_messgae += self.check_return_location_completeness()["error"]
                    if not self.check_path_completeness()["success"]:
                        error_messgae += self.check_path_completeness()["error"]
                    messages.append({ "role": "user", "content": error_messgae })
                    self.analysis_logger.info(f"USER prompt in error case: {error_messgae}")
                    self.result_logger.info(f"USER prompt in error case: {error_messgae}")
                    response = self.send_message(messages, allowed_tools)
                    if not response.content:
                        response.content = ""
                    self.analysis_logger.info(f"Model response: {response.content}")
                    messages.append(response)
                    continue

                for tool_call in response.tool_calls:
                    tool_function_name = tool_call.function.name
                    try:
                        tool_arguments = safe_load_json(tool_call.function.arguments)
                    except Exception as e:
                        self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                        function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                        messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
                        continue
                    self.analysis_logger.info(f"Tool call: {tool_function_name} with args: {tool_arguments}")

                    if tool_function_name == "create_path":
                        function_response = self.create_path_Tool(
                            **tool_arguments,
                            path_id=path_idx
                        )
                        path_idx += 1
                    elif tool_function_name == "add_path_gep_to_baseobj":
                        function_response = self.add_path_gep_to_baseobj_Tool(
                            **tool_arguments,
                            basic_info=basic_info
                        )
                    elif tool_function_name == "add_path_gep_to_member":
                        function_response = self.add_path_gep_to_member_Tool(
                            **tool_arguments,
                            basic_info=basic_info
                        )
                    elif tool_function_name == "complete_path":
                        function_response = self.complete_path_Tool(
                            **tool_arguments,
                            basic_info=basic_info
                        )
                    elif tool_function_name in self.tool_method_map:
                        tool_method = self.tool_method_map[tool_function_name]
                        function_response = tool_method(**tool_arguments) if tool_arguments else tool_method()
                    else:
                        self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                        function_response = {"error": f"Tool '{tool_function_name}' not found."}

                    if not isinstance(function_response, str):
                        function_response = json.dumps(function_response, ensure_ascii=False, indent=2)

                    self.analysis_logger.info(f"Tool response: {function_response}")
                    messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })

                response = self.send_message(messages, allowed_tools)
                if not response.content:
                    response.content = ""
                self.analysis_logger.info(f"Model response: {response.content}")
                messages.append(response) 
        except Exception as e:
            self.analysis_logger.exception("Failed during analysis_function_paths interaction")
            raise

        new_analysis_paths = []
        for path in self.tmp_path_list:
            if path["status"] == "deleted":
                continue
            new_analysis_path = copy.deepcopy(previous_analysis_path)
            new_analysis_path.extend(path["path_items"])
            new_analysis_paths.append(new_analysis_path)
        return new_analysis_paths

    def responseForAlter(self, alter: memory_defect.MemoryLeak):
        self.result_logger.info(f"\n ================================ Analysis started for Alter ================================ \n")
        self.result_logger.info(f"Alter: {alter.to_prompt()}")
        self.result_logger.info(f"\n ================================ Analysis started for Alter ================================ \n")
        self.analysis_logger.info(f"\n ================================ Analysis started for Alter ================================ \n")
        self.analysis_logger.info(f"Alter: {alter.to_prompt()}")
        self.analysis_logger.info(f"\n ================================ Analysis started for Alter ================================ \n")
        
        self.alter_prompt = alter.to_goal_prompt()
        start_loc = alter.get_source_location()
        current_function = analysis_operators.find_current_function(start_loc)
        if "error" in current_function:
            self.analysis_logger.error(f"Cannot find current function at {start_loc}")
            return None
        # 找到当前要追踪的变量名
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        if not variable_name:
            # 这一行可以是return malloc / alloc
            # 但是其实就是多加一步寻找所有调用位置
            # 先组装analysis_path_item
            analysis_path_item = {
                "value_object": variable_name,
                "start_location": start_loc,
                "function_name": current_function["function_name"],
                "return_location": start_loc,
                "classification": "Returned",
                "source_location": start_loc,
                "reason": f"The function {current_function['function_name']} returns the memory at {start_loc} : {find_code_line(start_loc)} directly to the caller."
            }
            # 加入一条analysis path
            analysis_path = [analysis_path_item]
            call_sites = analysis_operators.find_callers(current_function["function_name"])
            for call_site in call_sites:
                call_site_loc = call_site["location"]
                call_site_code = call_site["code"]
                caller_function = analysis_operators.find_current_function(call_site_loc)
                left_value = extract_lhs_variable(call_site_code)
                if left_value:
                    if left_value in self.global_variables:
                        # TODO
                        # 这里需要重新组装一个返回给全局变量的analysis_path_item
                        continue
                    else:
                        # 这里相当于继续分析
                        eq_position = analysis_operators.get_var_store_cl(call_site_loc, left_value)
                        analysis_path_list = self.analysis_function_paths(start_loc=call_site_loc, previous_analysis_path=analysis_path, current_function=caller_function, mode={"mode" : "local variable", "arg": eq_position}, var_name=left_value)
                        continue
                else:
                    self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Returned but no left value")
                    self.result_logger.info(f"\n ================================ Analysis terminated with Returned but no left value ================================ \n")
                    self.result_logger.info(f"Analysis path {analysis_path} terminated with Returned but no left value")
                    self.result_logger.info(f"\n ================================ Analysis terminated with Returned but no left value ================================ \n")
                    return analysis_path              
        else:
            eq_position = analysis_operators.get_var_store_cl(start_loc, variable_name)
            analysis_path_list = self.analysis_function_paths(start_loc=start_loc, previous_analysis_path=[], current_function=current_function, mode={"mode" : "local variable", "arg": eq_position}, var_name=variable_name)
        
        
        while True:
            all_done = True
            for analysis_path in analysis_path_list:
                if analysis_path[-1]["classification"] != "done":
                    all_done = False
                    break
            if all_done:
                self.analysis_logger.info(f"All analysis paths are done")
                self.result_logger.info(f"\n ================================ All analysis {len(analysis_path_list)} paths are done ================================ \n")
                self.result_logger.info(f"Analysis path list: {analysis_path_list}")
                self.result_logger.info(f"\n ================================ All analysis {len(analysis_path_list)} paths are done ================================ \n")
                break
            
            # 遍历副本，但修改真实的 analysis_path_list
            for analysis_path in analysis_path_list.copy():
                # debug 输出analysis_path
                print(f" ================================ Analysis path ================================ ")
                print(f"analysis_path: {analysis_path}")
                print(f" ================================ Analysis path ================================ ")
                last_analysis_path_item = analysis_path[-1]
                if last_analysis_path_item["classification"] == "done":
                    # 终止符号 这条分析路径已经分析完了
                    continue
                elif last_analysis_path_item["classification"] == "NullPointer" or last_analysis_path_item["classification"] == "Unreachable":
                    # 这条分析路径终止了
                    # 加入一个元素classification done
                    analysis_path.append({"classification": "done"})
                    self.analysis_logger.info(f"Analysis path {analysis_path} terminated with NullPointer or Unreachable")
                    self.result_logger.info(f"Analysis path {analysis_path} terminated with NullPointer or Unreachable")
                    continue
                elif last_analysis_path_item["classification"] == "Leak":
                    # 整个分析都可以终止了 报告最终结果为leak alter为正报
                    # TODO 
                    # 这里应该组织警报信息 将这条路径上的内容tostring展示出来
                    self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Leak")
                    self.result_logger.info(f"\n ================================ Analysis terminated with Leak ================================ \n")
                    self.result_logger.info(f"Analysis path: {analysis_path}")
                    self.result_logger.info(f"\n ================================ Analysis terminated with Leak ================================ \n")
                    return analysis_path
                elif last_analysis_path_item["classification"] == "Handled by callee":
                    free_loc = last_analysis_path_item["source_location"]
                    free_code_line = find_code_line(free_loc)
                    free_function_name = last_analysis_path_item["arg"]
                    free_function = analysis_operators.find_function_body(free_function_name)
                    fc_name, free_arg_index = get_arg_index(free_code_line, variable_name)
                    if free_function_name == "free":
                        # 这条分析路径终止了
                        analysis_path.append({"classification": "done"})
                        self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                        self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                        continue
                    else:
                        if {
                            "function_name": free_function_name,
                            "arg_index": free_arg_index
                        } in self.memcached:
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            analysis_path.append({"classification": "done"})
                            continue
                        free_function = analysis_operators.find_function_body(free_function_name)
                        self.memcached.append({
                            "function_name": free_function_name,
                            "arg_index": free_arg_index
                        })
                        print(f"free_function: {free_function}")
                        var_name = get_formal_arg_names(find_code_line(f"{free_function["filename"]}:{free_function["start_line"]}"))[free_arg_index]
                        analysis_path_list.remove(analysis_path)
                        new_analysis_path_list = self.analysis_function_paths(start_loc=free_function["start_line"], previous_analysis_path=analysis_path, current_function=free_function, mode={"mode" : "formal argument", "arg": free_arg_index}, var_name=var_name)
                        analysis_path_list.extend(new_analysis_path_list)
                        continue
                elif last_analysis_path_item["classification"] == "Returned":
                    # 寻找所有的调用位置
                    call_sites = analysis_operators.find_callers(current_function["function_name"])
                    for call_site in call_sites:
                        call_site_loc = call_site["location"]
                        call_site_code = call_site["code"]
                        left_value = extract_lhs_variable(call_site_code)
                        if left_value:
                            if left_value in self.global_variables:
                                # 表明分析已经完全结束 内存由全局变量管理 不需要再分析
                                analysis_path.append({"classification": "done"})
                                self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Returned")
                                self.result_logger.info(f"Analysis path {analysis_path} terminated with Returned")
                                continue
                            else:
                                # 继续进行分析 调用者函数内 左值内存是什么状况
                                eq_position = analysis_operators.get_var_store_cl(call_site_loc, left_value)
                                analysis_path_list.remove(analysis_path)
                                new_analysis_path_list = self.analysis_function_paths(start_loc=call_site_loc, previous_analysis_path=analysis_path, current_function=current_function, mode={"mode" : "local variable", "arg": eq_position}, var_name=left_value)
                                analysis_path_list.extend(new_analysis_path_list)
                                continue
                        else:
                            # 很奇怪 成为返回值 但是这个返回值没有被其他变量接收
                            # 暂时判断为leak
                            # TODO:
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Returned but no left value")
                            self.result_logger.info(f"\n ================================ Analysis terminated with Returned but no left value ================================ \n")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Returned but no left value")
                            self.result_logger.info(f"\n ================================ Analysis terminated with Returned but no left value ================================ \n")
                            return analysis_path
                    continue
                elif last_analysis_path_item["classification"] == "Transferred with assignment":
                    # 先通过赋值语句找到是哪个左值 等号
                    transfer_loc = last_analysis_path_item["source_location"]
                    claimed_arg = last_analysis_path_item["arg"]
                    transfer_function = analysis_operators.find_current_function(transfer_loc)
                    eq_position = analysis_operators.get_var_store_cl(transfer_loc, claimed_arg)
                    if eq_position is None:
                        self.analysis_logger.error(f"Cannot find eq position for {claimed_arg} at {transfer_loc}")
                        self.result_logger.error(f"Cannot find eq position for {claimed_arg} at {transfer_loc}")
                        return analysis_path
                    # 先使用trace lvar base object来找到base对象
                    base_lvar_def_json = analysis_operators.find_base_lvar_def(transfer_loc, eq_position)
                    # 这里要提前处理 保证模型说的就是准确的
                    # TODO:
                    self.analysis_logger.info(f"base_lvar_def_json: {base_lvar_def_json}")
                    err = base_lvar_def_json.get("error", None)
                    if err:
                        print(f"base_lvar_def_json: {base_lvar_def_json}")
                        self.analysis_logger.error(f"Cannot find base lvar def for {transfer_loc} at {eq_position}")
                        self.result_logger.error(f"Cannot find base lvar def for {transfer_loc} at {eq_position}")
                        return analysis_path
                    direct_def_node_json = base_lvar_def_json["direct_def_node"]
                    final_def_node_json = base_lvar_def_json["final_def_node"]
                    # 先解析direct_def_node_json 的 location 如果和 如果这个位置和起始分析的位置一致 说明应当追踪这里的base变量
                    last_start_loc = last_analysis_path_item["start_location"]
                    # 这个location是原始形式 要解析出来
                    # { \"ln\": 2855, \"cl\": 2, \"fl\": \"tif_getimage.c\" }
                    node_kind = ""
                    node_location = ""
                    direct_def_node_loc = get_location_from_desc(direct_def_node_json["location"])
                    if direct_def_node_loc == last_start_loc:
                        # 说明应当追踪这里的base变量
                        # base 位置也可能是函数参数
                        node_kind = final_def_node_json["kind"]
                        node_location = get_location_from_desc(final_def_node_json["location"])
                    else:
                        # 直接使用direct_def_node_loc即可
                        node_kind = direct_def_node_json["kind"]
                        node_location = direct_def_node_loc
                    if node_kind == "FormalParmVFGNode":
                        # 表明这里的左值是函数参数 看是第几个参数？
                        # 找到之前分析的函数的函数体的第一行/函数声明带参数的行
                        transfer_function_start_line = transfer_function["start_line"]
                        transfer_function_start_code_line = find_code_line(f"{transfer_function['filename']}:{transfer_function_start_line}")
                        _, actual_arg_index = get_arg_index(transfer_function_start_code_line, claimed_arg)
                        if actual_arg_index is None:
                            self.analysis_logger.error(f"Cannot find actual arg index for {claimed_arg} at {transfer_function_start_code_line}")
                            self.result_logger.error(f"Cannot find actual arg index for {claimed_arg} at {transfer_function_start_code_line}")
                            actual_arg_index = 0
                        transfer_function_call_sites = analysis_operators.find_callers(transfer_function["function_name"])
                        analysis_path_list.remove(analysis_path)
                        # 如果一个call sites都没有？ 死代码应该不会被分析到
                        for call_site in transfer_function_call_sites:
                            call_site_loc = call_site["location"]
                            call_site_code = call_site["code"]
                            print(f"call_site_code: {call_site_code}")
                            print(f"call_site_loc: {call_site_loc}")
                            self.analysis_logger.info(f"call_site_code: {call_site_code}")
                            self.analysis_logger.info(f"call_site_loc: {call_site_loc}")
                            caller_function = analysis_operators.find_current_function(call_site_loc)
                            # 追踪call arg模式下的第actual_arg_index个参数
                            var_name = get_actual_arg_names(call_site_code)[actual_arg_index]
                            new_analysis_path_list = self.analysis_function_paths(start_loc=call_site_loc, previous_analysis_path=analysis_path, current_function=caller_function, mode={"mode" : "call argument", "arg": actual_arg_index}, var_name=var_name)
                            analysis_path_list.extend(new_analysis_path_list)
                        continue
                    else:
                        # 表明这里的左值是变量
                        if claimed_arg in self.global_variables:
                            # 表明分析已经完全结束 内存由全局变量管理 不需要再分析
                            analysis_path.append({"classification": "done"})
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Transferred with assignment to global variable")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Transferred with assignment to global variable")
                            continue
                        else:
                            analysis_path_list.remove(analysis_path)
                            new_analysis_path_list = self.analysis_function_paths(start_loc=transfer_loc, previous_analysis_path=analysis_path, current_function=transfer_function, mode={"mode" : "local variable", "arg": eq_position}, var_name=claimed_arg)
                            analysis_path_list.extend(new_analysis_path_list)
                            continue
        return analysis_path_list
    
    
class DeepSeekPathAnalyzer(PathAnalyzerModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
    
    def DeepSeekAdapter(self, source_location, code):
        # DeepSeek 对行号的处理能力实在太差了
        # 假定他给出的代码是合理 准确的 修正code line number 我们认为他的准确性在+-2行以内 否则输出错误信息
        code_line_number = source_location.split(":")[1]
        code_line_number = int(code_line_number)
        for i in range(-2, 3):
            if code_line_number + i > 0:
                candidate_code_line = find_code_line(f"{source_location.split(':')[0]}:{code_line_number + i}")
                if candidate_code_line == code or candidate_code_line == code.strip():
                    return f"{source_location.split(':')[0]}:{code_line_number + i}"
        return {"error": f"mismatched code line number for {source_location} : {find_code_line(source_location)} and {code}"}
    
    def complete_path_Tool(self, path_id, classification, reason, source_location=None, code_line=None, arg=None, basic_info={}):
        if source_location is not None:
            source_location = self.DeepSeekAdapter(source_location, code_line)
            if "error" in source_location:
                return {"error": source_location["error"]}
        return super().complete_path_Tool(path_id, classification, reason, source_location, code_line, arg, basic_info)
    
      
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
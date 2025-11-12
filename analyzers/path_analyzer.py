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
    complete_path_desc_path,
    query_paths_desc_path,
    delete_path_desc_path
)
import re

logger = logging.getLogger(__name__)

from abc import ABC, abstractmethod
from openai import OpenAI
import memory_defect

import analysis_operators


class PathAnalyzerModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis")
        self.result_logger = setup_logger(log_type="result")
        self.global_variables = []
        self.memcached_callee_functions = []
        self.memcached_call_sites = []
        self.analysis_path_list = []
    
    def create_function_path_agent(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt):
        return FunctionPathAgent(current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt)
    
    def check_analysis_path_completeness(self):
        for analysis_path in self.analysis_path_list:
            if "classification" not in analysis_path:
                return False
            elif analysis_path["classification"] == "done":
                continue
            else:
                return False
        return True

    def build_lvar_gep_info(self, start_loc):
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        lvar_store_cl = analysis_operators.get_var_store_cl(start_loc, variable_name)
        lvar_analysis_info = analysis_operators.analysis_lvar(start_loc, lvar_store_cl)
        if "gep_info" in lvar_analysis_info:
            gep_info = lvar_analysis_info["gep_info"]
            code_line = find_code_line(start_loc, strip_whitespace=False)
            member_name = code_line[(gep_info["gep_cl"]-1):lvar_store_cl].rstrip("=").strip()
            gep_info["member_name"] = member_name
            gep_info["baseobj_name"] = code_line[:(gep_info["gep_cl"]-1)].lstrip("(").lstrip().rstrip("->").rstrip(".").strip()
        else:
            gep_info = {
                "gep_type": "not_struct",
                "member_name": None,
                "baseobj_name": None,
                "offset": None,
                "baseobj_type": None,
            }
        return gep_info
    
    def check_lvar_param(self, start_loc):
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        lvar_store_cl = analysis_operators.get_var_store_cl(start_loc, variable_name)
        lvar_analysis_info = analysis_operators.analysis_lvar(start_loc, lvar_store_cl)
        return lvar_analysis_info["is_lvar_param"]
    
    def responseForAlter(self, alter : memory_defect.MemoryLeak):
        self.alter_prompt = alter.to_goal_prompt()
        start_loc = alter.get_source_location()
        current_function_info = analysis_operators.find_current_function(start_loc)
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        var_info = {}
        if variable_name is None:
            # 表明是return malloc
            function_analysis_path = {
                "value_object": None,
                "function_name": current_function_info["function_name"],
                "start_location": start_loc,
                "classification": "Returned to caller",
                "event_location": start_loc,
                "reason": f"The function {current_function_info['function_name']} returns the memory at {start_loc} : {find_code_line(start_loc)} directly to the caller."
            }
            self.analysis_path_list.append(function_analysis_path)
            call_sites = analysis_operators.find_callers(current_function_info["function_name"])
            for call_site in call_sites:
                call_site_location = call_site["location"]
                call_site_code = call_site["code"]
                if call_site_location in self.memcached_call_sites:
                    continue
                else:
                    self.memcached_call_sites.append(call_site_location)
                caller_function = analysis_operators.find_current_function(call_site_location)
                left_var = extract_lhs_variable(call_site_code)
                gep_info = self.build_lvar_gep_info(call_site_location)
                if left_var is None:
                    # leak
                    return
                else:
                    var_info.update({
                        "var_name": left_var,
                        "var_type": "local_var",
                        "arg_index": analysis_operators.get_eq_position_list(call_site_location, left_var),
                        "gep_info": {
                            "gep_type": gep_info["gep_type"],
                            "baseobj_name": gep_info["baseobj_name"],
                            "member_name": gep_info["member_name"],
                            "offset": gep_info["offset"],
                            "baseobj_type": gep_info["baseobj_type"],
                        },
                    })
                    if left_var in self.global_variables:
                        # 全局变量
                        continue
                    else:
                        # 创建一个FunctionPathAgent实例 并调用其analysis_function_paths方法
                        function_path_agent = self.create_function_path_agent(caller_function, var_info, call_site_location, self.analysis_path_list)
                        self.analysis_path_list = function_path_agent.analysis_function_paths()
        else:
            gep_info = self.build_lvar_gep_info(start_loc)
            var_info.update({
                "var_name": variable_name,
                "var_type": "local_var",
                "arg_index": analysis_operators.get_var_store_cl(start_loc, variable_name),
                "gep_info": {
                    "gep_type": gep_info["gep_type"],
                    "baseobj_name": gep_info["baseobj_name"],
                    "member_name": gep_info["member_name"],
                    "offset": gep_info["offset"],
                    "baseobj_type": gep_info["baseobj_type"],
                },
            })
            function_path_agent = self.create_function_path_agent(current_function_info, var_info, start_loc, self.analysis_path_list, self.alter_prompt)
            self.analysis_path_list = function_path_agent.analysis_function_paths()
        
        print(f"analysis_path_list: {self.analysis_path_list}")
        
        while True:
            if self.check_analysis_path_completeness():
                break
            for analysis_path in self.analysis_path_list.copy():
                print(f"analysis_path: {analysis_path}")
                last_function_analysis_path = analysis_path[-1]
                if last_function_analysis_path["classification"] == "done":
                    continue
                last_function_name = last_function_analysis_path["function_name"]
                last_var_info = last_function_analysis_path["var_info"]
                if last_function_analysis_path["classification"] == "Returned to caller":
                    # 返回给调用者
                    # 这里有两种情况 要么是作为参数被转移 要么是真的作为返回值被转移了
                    # 以前只处理了后者
                    # 寻找所有的调用位置
                    call_sites = analysis_operators.find_callers(last_function_name)
                    previous_analysis_path = copy.deepcopy(analysis_path)
                    self.analysis_path_list.remove(analysis_path)
                    if last_function_analysis_path["arg"] == "return_value":
                        for call_site in call_sites:
                            call_site_loc = call_site["location"]
                            call_site_code = call_site["code"]
                            if call_site_loc in self.memcached_call_sites:
                                continue
                            else:
                                self.memcached_call_sites.append(call_site_loc)
                            left_value = extract_lhs_variable(call_site_code)
                            if left_value:
                                if left_value in self.global_variables:
                                    # 表明分析已经完全结束 内存由全局变量管理 不需要再分析
                                    current_analysis_path = copy.deepcopy(previous_analysis_path)
                                    current_analysis_path.append({"classification": "done"})
                                    self.analysis_path_list.append(current_analysis_path)
                                    self.analysis_logger.info(f"Analysis path {current_analysis_path} terminated with Returned")
                                    self.result_logger.info(f"Analysis path {current_analysis_path} terminated with Returned")
                                    continue
                                else:
                                    # 继续进行分析 调用者函数内 左值内存是什么状况
                                    var_info = {
                                        "var_name": left_value,
                                        "var_type": "local_var",
                                        "arg_index": analysis_operators.get_eq_position_list(call_site_loc, left_value),
                                        "gep_info": self.build_lvar_gep_info(call_site_loc),
                                    }
                                    current_analysis_path = copy.deepcopy(previous_analysis_path)
                                    caller_function_info = analysis_operators.find_current_function(call_site_loc)
                                    function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site_loc, current_analysis_path, self.alter_prompt)
                                    self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
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
                    else:
                        # 查询上一个函数的参数列表 找var info中的名字是第几个参数
                        last_function_info = analysis_operators.find_function_body(last_function_name)
                        formal_arg_name_list = get_formal_arg_names(find_code_line(f"{last_function_info['filename']}:{last_function_info['start_line']}"))
                        var_name = last_var_info["var_name"]
                        if var_name in formal_arg_name_list:
                            arg_index = formal_arg_name_list.index(var_name)
                            # 表明在调用者那边作为了第arg_index个参数
                            for call_site in call_sites:
                                if call_site_loc in self.memcached_call_sites:
                                    continue
                                else:
                                    self.memcached_call_sites.append(call_site_loc)
                                call_site_loc = call_site["location"]
                                call_site_code = call_site["code"]
                                # 对应第arg_index个参数
                                var_info = {
                                    "var_name": get_actual_arg_names(call_site_code, last_function_name)[arg_index],
                                    "var_type": "actual_arg",
                                    "arg_index": arg_index,
                                    "gep_info": last_var_info["gep_info"]
                                }
                                current_analysis_path = copy.deepcopy(previous_analysis_path)
                                function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site_loc, current_analysis_path, self.alter_prompt)
                                self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
                        else:
                            gep_type = last_var_info["gep_info"]["gep_type"]
                            if gep_type == "baseobj":
                                # baseobj 转移了 但是没有在实参列表中出现
                                # 这种情况比较少见 暂时认为leak
                                self.analysis_logger.error(f"Baseobj {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                self.result_logger.error(f"Baseobj {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                return analysis_path
                                member_name = last_var_info["gep_info"]["member_name"]
                                if member_name in formal_arg_name_list:
                                    arg_index = formal_arg_name_list.index(member_name)
                                    # 表明在调用者那边作为了第arg_index个参数
                                    # 组装新的var_info[gep_info]
                                    for call_site in call_sites:
                                        call_site_loc = call_site["location"]
                                        call_site_code = call_site["code"]
                                        # 对应第arg_index个参数
                                        var_info = {
                                            "var_name": get_actual_arg_names(call_site_code)[arg_index],
                                            "var_type": "actual_arg",
                                            "arg_index": arg_index,
                                        }
                                        # 这个地方其实也不合理 追踪的变量作为base value 但是只有member出现在形参中
                                else:
                                    # 这个地方有问题 log相关信息
                                    self.analysis_logger.error(f"Cannot find member name {member_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    self.result_logger.error(f"Cannot find member name {member_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    return analysis_path
                            elif gep_type == "member":
                                baseobj_name = last_var_info["gep_info"]["baseobj_name"]
                                if baseobj_name in formal_arg_name_list:
                                    arg_index = formal_arg_name_list.index(baseobj_name)
                                    # 表明在调用者那边作为了第arg_index个参数
                                    # 组装新的var_info[gep_info]
                                    for call_site in call_sites:
                                        call_site_loc = call_site["location"]
                                        call_site_code = call_site["code"]
                                        if call_site_loc in self.memcached_call_sites:
                                            continue
                                        else:
                                            self.memcached_call_sites.append(call_site_loc)
                                        # 对应第arg_index个参数
                                        var_info = {
                                            "var_name": get_actual_arg_names(call_site_code, last_function_name)[arg_index],
                                            "var_type": "actual_arg",
                                            "arg_index": arg_index,
                                        }
                                        # gep转为baseobj
                                        var_info["gep_info"] = last_var_info["gep_info"]
                                        var_info["gep_info"]["gep_type"] = "baseobj"
                                        current_analysis_path = copy.deepcopy(previous_analysis_path)
                                        caller_function_info = analysis_operators.find_current_function(call_site_loc)
                                        function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site_loc, current_analysis_path, self.alter_prompt)
                                        self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
                                else:
                                    # 这个地方有问题 log相关信息
                                    self.analysis_logger.error(f"Cannot find baseobj name {baseobj_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    self.result_logger.error(f"Cannot find baseobj name {baseobj_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    return analysis_path
                            else:
                                # 这就以为着非结构体的变量却没有在形式参数列表中找到
                                # 这个地方有问题 log信息
                                self.analysis_logger.error(f"Non-struct variable {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                self.result_logger.error(f"Non-struct variable {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                return analysis_path
                    continue
                elif last_function_analysis_path["classification"] == "Handled by callee":
                    # 被调用者处理
                    callee_function_name = last_function_analysis_path["arg"]
                    callee_function_info = analysis_operators.find_current_function(callee_function_name)
                    call_location = last_function_analysis_path["source_location"]
                    call_code = find_code_line(call_location)
                    last_var_info = last_function_analysis_path["var_info"]
                    formal_arg_gep_info = {}
                    if last_var_info["gep_info"]["gep_type"] == "not_struct":
                        fc_name, call_arg_index = get_arg_index(call_code, last_var_info["var_name"])
                        formal_arg_gep_info = last_var_info["gep_info"]
                    elif last_var_info["gep_info"]["gep_type"] == "baseobj":
                        fc_name, call_arg_index = get_arg_index(call_code, last_var_info["var_name"])
                        # gep baseobj
                        formal_arg_gep_info = last_var_info["gep_info"]
                        if fc_name is None:
                            fc_name, call_arg_index = get_arg_index(call_code, last_var_info["gep_info"]["member_name"])
                            # gep member
                            formal_arg_gep_info = last_var_info["gep_info"]
                            formal_arg_gep_info["gep_type"] = "member"
                    elif last_var_info["gep_info"]["gep_type"] == "member":
                        fc_name, call_arg_index = get_arg_index(call_code, last_var_info["gep_info"]["baseobj_name"])
                        # gep baseobj
                        formal_arg_gep_info = last_var_info["gep_info"]
                        formal_arg_gep_info["gep_type"] = "baseobj"
                        if fc_name is None:
                            fc_name, call_arg_index = get_arg_index(call_code, last_var_info["var_name"])
                            # gep member
                            formal_arg_gep_info = last_var_info["gep_info"]
                    # 实际上就是追踪formal arg / index为call_arg_index / function info为callee_function_info / 
                    if callee_function_name == "free":
                        analysis_path.append({"classification": "done"})
                        self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                        self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                    else:
                        if {
                            "function_name": callee_function_name,
                            "arg_index": call_arg_index
                        } in self.memcached:
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            analysis_path.append({"classification": "done"})
                            continue
                        # 判定需要多少了参数 只有当只需要一个参数才加入cached
                        # TODO
                        self.memcached.append({
                            "function_name": callee_function_name,
                            "arg_index": call_arg_index
                        })
                        # 组装var_info
                        var_info = {
                            "var_name": get_formal_arg_names(f"{callee_function_info["filename"]}:{callee_function_info["start_line"]}")[call_arg_index],
                            "var_type": "formal_arg",
                            "arg_index": call_arg_index,
                            "gep_info": formal_arg_gep_info
                        }
                        function_path_agent = self.create_function_path_agent(callee_function_info, var_info, callee_function_info["start_location"], self.analysis_path_list, self.alter_prompt)
                        self.analysis_path_list.remove(analysis_path)
                        self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
                    continue
                elif last_function_analysis_path["classification"] == "Transferred with assignment":
                    # transfer function : transfer发生的函数
                    # caller function : 调用transfer function的函数
                    transfer_location = last_function_analysis_path["source_location"]
                    transfer_function_info = analysis_operators.find_current_function(transfer_location)
                    var_name = last_function_analysis_path["arg"]
                    eq_position = analysis_operators.get_var_store_cl(transfer_location, var_name)
                    # get_var_store_cl这里一定成功 因为只有成功被才能被模型complete
                    # 可能是转移给了局部变量 可能是转移给了全局变量 可能是转移给了函数参数
                    if self.check_lvar_param(transfer_location):
                        # 转移给了函数参数
                        # 找到之前分析的函数的首行 带有函数参数的一行
                        transfer_function_start_line = transfer_function_info["start_line"]
                        transfer_function_start_code_line = find_code_line(f"{transfer_function_info['filename']}:{transfer_function_start_line}")
                        _, actual_arg_index = get_arg_index(transfer_function_start_code_line, var_name)
                        if actual_arg_index is None:
                            self.analysis_logger.error(f"Cannot find actual arg index for {var_name} at {transfer_function_start_code_line}")
                            self.result_logger.error(f"Cannot find actual arg index for {var_name} at {transfer_function_start_code_line}")
                            actual_arg_index = 0
                        transfer_function_call_sites = analysis_operators.find_callers(transfer_function_info["function_name"])
                        previous_analysis_path = copy.deepcopy(analysis_path)
                        self.analysis_path_list.remove(analysis_path)
                        # 如果一个call sites都没有？ 死代码应该不会被分析到
                        for call_site in transfer_function_call_sites:
                            # 追踪call arg模式下的第actual_arg_index个参数
                            # 组装var_info
                            call_site_loc = call_site["location"]
                            if call_site_loc in self.memcached_call_sites:
                                continue
                            else:
                                self.memcached_call_sites.append(call_site_loc)
                            var_info = {
                                "var_name": get_actual_arg_names(find_code_line(call_site["location"], transfer_function_info["function_name"]))[actual_arg_index],
                                "var_type": "actual_arg",
                                "arg_index": actual_arg_index,
                            }
                            var_info["gep_info"] = last_var_info["gep_info"]
                            caller_function_info = analysis_operators.find_current_function(call_site["location"])
                            function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site["location"], previous_analysis_path, self.alter_prompt)
                            self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
                    else:
                        # 转移给了局部变量 或 全局变量
                        if var_name in self.global_variables:
                            analysis_path.append({"classification": "done"})
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Transferred with assignment and global variable")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Transferred with assignment and global variable")
                            continue
                        else:
                            self.analysis_path_list.remove(analysis_path)
                            var_info = {
                                "var_name": var_name,
                                "var_type": "local_var",
                                "arg_index": analysis_operators.get_eq_position_list(transfer_location, var_name),
                                "gep_info": self.build_lvar_gep_info(transfer_location),
                            }
                            function_path_agent = self.create_function_path_agent(transfer_function_info, var_info, transfer_location, self.analysis_path_list, self.alter_prompt)
                            self.analysis_path_list.extend(function_path_agent.analysis_function_paths())
                    continue
                else: 
                    # Unreachable # NullPointer
                    # 删除原来的path
                    previous_analysis_path = copy.deepcopy(analysis_path)
                    self.analysis_path_list.remove(analysis_path)
                    previous_analysis_path.append({"classification": "done"})
                    self.analysis_path_list.append(previous_analysis_path)
                    continue
            
    
class DeepSeekPathAnalyzer(PathAnalyzerModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
    
    def create_function_path_agent(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt):
        return FunctionPathAgent(current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt, self.client, self.model_name)
    
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
    
    def create_function_path_agent(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt):
        return FunctionPathAgent(current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt, self.client, self.model_name)


class FunctionPathAgent():
    def __init__(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt, client=None, model_name=None):
        self.path_idx = 0
        self.client = client
        self.model_name = model_name
        self.alter_prompt = alter_prompt
        self.current_function_info = current_function_info
        self.var_info = var_info
        # var_info: {
        #     "var_name": var_name,
        #     "var_type": "formal_arg" | "actual_arg" | "local_var",
        #     "arg_index": arg_index 如果是formal_arg或actual_arg 则是参数在函数中的索引 如果是local_var 则是局部变量在赋值语句中对应的eq_position
        #     "gep_info": {
        #         "gep_type": "baseobj" | "member" | "not_struct",
        #         "baseobj_name": baseobj_name,
        #         "member_name": member_name,
        #         "offset": offset
        #         "baseobj_type": baseobj_type,
        #     }
        # }
        self.start_location = start_location
        self.previous_analysis_path_list = previous_analysis_path_list
        self.return_location_list = []
        # [
        #     {
        #         'return_location': 'tif_read.c:1417',
        #         'completed_path_number': 0,
        #         'possible_path_list': [],
        #         'possible_path_number': 0,
        #     },
        #     {
        #         'return_location': 'tif_read.c:1431',
        #         'completed_path_number': 0,
        #         'possible_path_list': [],
        #         'possible_path_number': 1,
        #     },
        #     {
        #         'return_location': 'tif_read.c:1429',
        #         'completed_path_number': 0,
        #         'possible_path_list': [],
        #         'possible_path_number': 1,
        #     },
        # ]
        self.function_analysis_path_list = []
        # [{
        #     "path_id": path_id,
        #    "return_location": return_location,
        #    "status": "active" | "completed" | "deleted",
        #    "path_items": [
        #        {
        #            "value_object": value_object,
        #            "function_name": function_name,
        #            "classification": classification,
        #            "source_location": source_location,
        #            "reason": reason
        #        }
        #    ],
        #    "description": description
        # }, ...]
        self.tool_method_map = {
            "create_path": self.create_path_Tool,
            "complete_path": self.complete_path_Tool,
            "query_paths": self.query_paths_Tool,
            "delete_path": self.delete_path_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
        }
        print(
            "[FunctionPathAgent] init function=%s var=%s start=%s previous_paths=%d client=%s"
            % (
                (self.current_function_info or {}).get("function_name"),
                (self.var_info or {}).get("var_name"),
                self.start_location,
                len(self.previous_analysis_path_list) if isinstance(self.previous_analysis_path_list, list) else 0,
                "provided" if client else "none",
            )
        )
    
    # 管理函数
    def build_analysis_path(self):
        # previous_analysis_path_list: [{function1 analysis path}, {function2 analysis path}, ...]
        # self.function_analysis_path_list: [{current function analysis path1}, {current function analysis path2}, ...]
        # build -> [[previous analysis path, current function analysis path1], [previous analysis path, current function analysis path2], ...]
        new_analysis_path_list = []
        for current_function_analysis_path in self.function_analysis_path_list:
            if current_function_analysis_path["status"] == "completed":
                new_analysis_path = copy.deepcopy(self.previous_analysis_path_list)
                new_analysis_path.append(current_function_analysis_path["path_items"])
                new_analysis_path_list.append(new_analysis_path)
        print(
            "[FunctionPathAgent] build_analysis_path new_analysis_path_list=%d"
            % (len(new_analysis_path_list))
        )
        print(f"new_analysis_path_list: {new_analysis_path_list}")
        return new_analysis_path_list

    def send_message(self, messages, tools=""):
        tool_count = len(tools) if isinstance(tools, (list, tuple)) else (len(tools) if tools else 0)
        print(
            "[FunctionPathAgent] send_message model=%s messages=%d tools=%d"
            % (getattr(self, "model_name", "unknown"), len(messages), tool_count)
        )
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        print(
            "[FunctionPathAgent] response content=%s"
            % (response.choices[0].message.content if response.choices[0].message else None)
        )
        print(
            "[FunctionPathAgent] received response has_content=%s tool_calls=%d"
            % (
                bool(response.choices[0].message.content),
                len(response.choices[0].message.tool_calls or []),
            )
        )
        return response.choices[0].message  
    
    def check_return_location_completeness(self):
        # 找出所有未完成的return location
        incomplete_return_locations = []
        for return_location_info in self.return_location_list:
            if return_location_info["completed_path_number"] == 0 and return_location_info["possible_path_number"] > 0:
                incomplete_return_locations.append(return_location_info["return_location"])
        return incomplete_return_locations
    
    def check_path_completeness(self):
        incomplete_paths = []
        for path in self.function_analysis_path_list:
            if path["status"] == "active":
                incomplete_paths.append(path["path_id"])
        return incomplete_paths
    
    # agent工具函数
    def handle_agent_tool_call(self, tool_call):
        try:
            function_obj = getattr(tool_call, "function", tool_call)
            function_name = getattr(function_obj, "name", None)
            if not function_name:
                raise ValueError("missing function name in tool call")
            raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
            tool_arguments = safe_load_json(raw_arguments)
            print("[FunctionPathAgent] tool_call name=%s arguments=%s" % (function_name, raw_arguments))
            if function_name == "create_path" and isinstance(tool_arguments, dict):
                tool_arguments.pop("path_id", None)
        except Exception as e:
            return {"error": f"failed to prepare tool call: {str(e)}"}

        handler = self.tool_method_map.get(function_name)
        if handler is None:
            return {"error": f"unknown tool function: {function_name}"}

        try:
            if isinstance(tool_arguments, dict):
                return handler(**tool_arguments)
            if isinstance(tool_arguments, list):
                return handler(*tool_arguments)
            return handler(tool_arguments)
        except TypeError as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}
        except Exception as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}
    
    # 源代码查询相关
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
        
    # path相关
    def create_path_Tool(self, return_location, description, path_id=None):
        if return_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', return_location):
            return {"error": f"invalid return_location: {return_location}"}
        # 校验return_location是否在return_locations中
        return_location_info = next(filter(lambda x: x["return_location"] == return_location, self.return_location_list), None)
        if return_location_info is None:
            return {"error": f"return_location {return_location} not found in return_locations."}
        path_id = str(self.path_idx)
        self.path_idx += 1
        new_path = {
            "path_id": path_id,
            "return_location": return_location,
            "status": "active",
            "path_items": None,
            "description": description
        }
        self.function_analysis_path_list.append(new_path)
        print("[FunctionPathAgent] create_path path_id=%s return_location=%s" % (path_id, return_location))
        return new_path

    def query_paths_Tool(self, path_id):
        # 暂时过滤掉deleted的path
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id and x["status"] != "deleted", self.function_analysis_path_list), None)
        if path is None:
            return {"error": f"path_id {path_id} not found or deleted."}
        return path

    def delete_path_Tool(self, path_id):
        path_id = str(path_id)
        # 找到要删除的目标path
        target_path = next(filter(lambda x: x["path_id"] == path_id, self.function_analysis_path_list), None)
        if target_path is None:
            return {"error": f"path_id {path_id} not found."}
        # 如果原先的状态为completed 则说明对应指向的return_location的completed_path_number需要减1
        if target_path["status"] == "completed":
            return_location = target_path["return_location"]
            return_location_info = next(filter(lambda x: x["return_location"] == return_location, self.return_location_list), None)
            return_location_info["completed_path_number"] -= 1
        target_path["status"] = "deleted"
        print("[FunctionPathAgent] delete_path path_id=%s" % path_id)
        return {"path_id": path_id, "status": "deleted"}

    # path核心分析功能完成位置 
    def complete_path_Tool(self, path_id, classification, reason, source_location=None, code_line=None, arg=None):
        path_id = str(path_id)
        print(
            "[FunctionPathAgent] complete_path path_id=%s classification=%s source_location=%s arg=%s"
            % (path_id, classification, source_location, arg)
        )
        path = next(filter(lambda x: x["path_id"] == path_id, self.function_analysis_path_list), None)
        if path is None:
            return {"error": f"path_id {path_id} not found."}
        if path["status"] == "deleted":
            return {"error": f"path_id {path_id} is deleted."}
        if path["status"] == "completed":
            return {"error": f"path_id {path_id} is completed."}
        return_location = path["return_location"]
        return_location_info = next(filter(lambda x: x["return_location"] == return_location, self.return_location_list), None)
        if return_location_info is None:
            return {"error": f"return_location {return_location} not found in return_locations."}
        if classification == "NullPointer":
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Transferred with assignment":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Transferred with assignment classification"}
            if arg is None:
                return {"error": f"arg is required for Transferred with assignment classification to specify which variable the memory was transferred to."}
            if self.start_location == source_location:
                return {"error": f"The source location {source_location} is the same as the start location {self.start_location}. Please check if the code line is correct or if the line is a gep or store operation."}
            eq_position_l = analysis_operators.get_eq_position_list(source_location)
            if eq_position_l is None:
                return {"error": f"The code line at {source_location} : {find_code_line(source_location)} has no related store statement. Please check if the code line is correct."}
            matched_arg = False
            # TODO 这里还需要匹配gep 如果base变量被转移也可以
            for eq_position in eq_position_l:
                code_line = find_code_line(source_location)
                if arg in code_line[:eq_position] and (self.var_info["var_name"] in code_line[:eq_position]):
                    matched_arg = True
                    break
            if not matched_arg:
                return {"error": f"Cannot identify \"{arg}\" as a left value and \"{self.var_info['var_name']}\" as a right value in an store statement in the code line at {source_location} : {find_code_line(source_location)}. Please check if the code line is correct or the arg is correct."}
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Returned to caller":
            # TODO 这里还需要匹配gep 如果参数自己 / 参数的baseobj在函数参数列表中被转移也可以
            return_pointer_json = analysis_operators.check_return_pointer(return_location)
            if return_pointer_json["function_can_return_pointer"] and return_pointer_json["location_has_pointer_operation"]:
                arg = "return_value"
            else:
                arg = "formal_arg"
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Handled by callee":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Handled by callee classification"}
            if arg is None:
                return {"error": f"arg is required for Handled by callee classification to specify which function was used to release the memory."}
            # TODO 这里还需要匹配gep 如果base变量被转移也可以
            extracted_function_name, arg_index = get_arg_index(code_line, self.var_info["var_name"])
            if extracted_function_name is None or arg_index is None:
                return {"error": f"Cannot find the function name and arg index in the code line at {source_location} : {find_code_line(source_location)} for the arg {self.var_info['var_name']}. You may just give the code line where the transfer happens or check if the code line is correct or the arg is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
            elif extracted_function_name != arg:
                return {"error": f"The function name {extracted_function_name} is not the same as the arg {arg}. Please check if the function name is correct. If a GEP operation occurs on the path, please add a path event and specify the exact BaseObjName and MemberName of the GEP operation."}
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "arg": arg
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Leak":
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Unreachable":
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": None,
                "reason": reason
            }
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        else:
            return {"error": f"unknown classification: {classification}"}
    
    # 维护这个方法来保证在一个函数中生成多个抵达返回位置的路径的分析    
    def analysis_function_paths(self):
        allowed_tools = [
            dump_source_snippet_desc_free, dump_source_line_desc_free, find_current_function_desc_free, find_function_body_desc_free, find_callers_desc_free,
            create_path_desc_path, complete_path_desc_path, query_paths_desc_path, delete_path_desc_path
        ]
        # 整理所有返回路径 每个返回路径指向一个return位置 一个return位置可能有多个返回路径
        if self.var_info["var_type"] == "formal_arg":
            self.arg_index = self.var_info["arg_index"]
            wappered_return_locations = analysis_operators.get_value_sensitive_arg_icfg_return_path(self.current_function_info["function_name"], self.arg_index)
            var_prompt = f"You are now tracing the memory of {self.var_info['var_name']} in the function {self.current_function_info['function_name']}. The variable is the {self.arg_index}th formal argument of this function."
        elif self.var_info["var_type"] == "actual_arg":    
            self.arg_index = self.var_info["arg_index"]
            wappered_return_locations = analysis_operators.get_value_sensitive_call_arg_icfg_return_path(self.start_location, self.arg_index, self.previous_analysis_path_list[-1]["function_name"])
            var_prompt = f"You are now tracing the memory of {self.var_info['var_name']} in the function {self.current_function_info['function_name']}. The variable is the {self.arg_index}th actual argument used to call {self.previous_analysis_path_list[-1]['function_name']}."
        elif self.var_info["var_type"] == "local_var":
            store_cl = self.var_info["arg_index"]
            wappered_return_locations = analysis_operators.get_value_sensitive_lvar_icfg_return_path(self.start_location, store_cl)
            var_prompt = f"You are now tracing the memory of {self.var_info['var_name']} in the function {self.current_function_info['function_name']}. The variable is a local variable."
        if self.var_info["gep_info"]["gep_type"] == "baseobj":
            var_prompt += f"The variable is a base object of a struct GEP operation. The base object name is {self.var_info['gep_info']['baseobj_name']} and the member name is {self.var_info['gep_info']['member_name']}."
        elif self.var_info["gep_info"]["gep_type"] == "member":
            var_prompt += f"The variable is a member of a struct GEP operation. The base object name is {self.var_info['gep_info']['baseobj_name']} and the member name is {self.var_info['gep_info']['member_name']}."
        else:
            var_prompt += f"The variable is a non-struct variable."
        function_prompt = f"current function {self.current_function_info['function_name']} contains the following code:\n{self.current_function_info['function_body']}\n"
        return_prompt = f"All possible paths to the return location of the function {self.current_function_info['function_name']} are as follows:\n"
        for wappered_return_location in wappered_return_locations:
            return_location_info = {
                "return_location": f"{wappered_return_location['location']["fl"]}:{wappered_return_location['location']["ln"]}",
                "completed_path_number" : 0,
                "possible_path_list" : [],
                "possible_path_number" : wappered_return_location["mergeable_groups"]
            }
            if return_location_info["possible_path_number"] > 1:
                for possible_path in wappered_return_location["path_groups"]:
                    group_items = read_group(possible_path)
                    return_location_info["possible_path_list"].append(group_items)
            self.return_location_list.append(return_location_info)
            if return_location_info["possible_path_number"] > 0:
                return_prompt += f"There may be {return_location_info['possible_path_number']} paths to the return location {return_location_info['return_location']}."
                if return_location_info["possible_path_number"] > 1:
                    for i in range(return_location_info["possible_path_number"]):
                        return_prompt += f"Path {i}: "
                        if return_location_info['possible_path_list'][i]:
                            for vfg_node_item in return_location_info['possible_path_list'][i]:
                                return_prompt += f"passed {vfg_node_item['vfg_node_kind']} at {vfg_node_item['location']} : {find_code_line(vfg_node_item['location'])}\n"                
                        else:
                            return_prompt += "basic path\n"
        return_prompt += f"You should claim the state of the variable {self.var_info['var_name']} (or the resource it holds) along all paths to the return point as following six categories:\n"
        return_prompt += f"The variable is always a null pointer (NullPointer).\n"
        return_prompt += f"Ownership of the memory has been transferred through an assignment to another variable (Transferred with assignment).\n"
        return_prompt += f"The memory is returned as return value to the caller or as (part of) an actual argument used to call a function (Returned to caller).\n"
        return_prompt += f"The memory will be handled by the callee (Handled by callee).\n"
        return_prompt += f"A memory leak has occurred (Leak).\n"
        return_prompt += f"This return point is unreachable (Unreachable), Or, this return point is unreachable because of conditional logic on the path.\n"
        return_prompt += "For each potential execution path, first use create_path to register it, record any struct GEP transitions with add_path_gep_to_baseobj or add_path_gep_to_member, and finalize the judgement with complete_path once you determine the classification. You may query or delete paths using query_paths and delete_path if necessary.\n"
        if self.previous_analysis_path_list:
            previous_analysis_path_prompt = "The previous analysis shows that there exists a path leads to current function as follows:\n"
            for previous_analysis_path_item in self.previous_analysis_path_list:
                previous_analysis_path_prompt += f"The memory of {previous_analysis_path_item['var_info']['var_name']} at {previous_analysis_path_item['start_location']} : {find_code_line(previous_analysis_path_item['start_location'])}"
                previous_analysis_path_prompt += f"is {previous_analysis_path_item['classification']} in the function {previous_analysis_path_item['function_name']}, and control flow will return at {previous_analysis_path_item['return_location']} : {find_code_line(previous_analysis_path_item['return_location'])}.\n"
                previous_analysis_path_prompt += f"with explanation that {previous_analysis_path_item['reason']}\n"
                if previous_analysis_path_item["classification"] == "Transferred with assignment":
                    previous_analysis_path_prompt += f"The memory is transferred from {previous_analysis_path_item['source_location']} : {find_code_line(previous_analysis_path_item['source_location'])} to the current function.\n"
                elif previous_analysis_path_item["classification"] == "Handled by callee":
                    previous_analysis_path_prompt += f"The memory is transferred as by a function call from {previous_analysis_path_item['function_name']} to the current function.\n"
                elif previous_analysis_path_item["classification"] == "Returned to caller":
                    previous_analysis_path_prompt += f"The memory is returned from the function call of {previous_analysis_path_item['function_name']} as {previous_analysis_path_item['arg']}. You may start from this return site.\n"
                
        else:
            previous_analysis_path_prompt = ""
        project_prompt = f"You are now working for project {PROJECT_NAME}. {PROJECT_DESC}\n"
        messages = [
            {"role": "system", "content": VALUE_PATH_PROMPT + project_prompt},
            {"role": "user", "content": self.alter_prompt + previous_analysis_path_prompt + var_prompt + function_prompt + return_prompt}
        ] 
        response = self.send_message(messages, allowed_tools)
        if not response.content:
            response.content = ""
        messages.append(response)
        # 处理模型返回的循环
        while True:
            # 如果没有模型返回，退出循环
            if not response.tool_calls:
                incomplete_return_locations = self.check_return_location_completeness()
                incomplete_paths = self.check_path_completeness()
                if len(incomplete_return_locations) > 0:
                    messages.append({ "role": "user", "content": f"The return locations {incomplete_return_locations} are not complete. Please create path to these return locations." })
                    response = self.send_message(messages, allowed_tools)
                    if not response.content:
                        response.content = ""
                    messages.append(response)
                    continue
                if len(incomplete_paths) > 0:
                    messages.append({ "role": "user", "content": f"The paths {incomplete_paths} are not complete. Please complete or delete these paths." })
                    response = self.send_message(messages, allowed_tools)
                    if not response.content:
                        response.content = ""
                    messages.append(response)
                    continue
                break
            # 处理每个模型返回
            for tool_call in response.tool_calls:
                function_response = self.handle_agent_tool_call(tool_call)
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                print("[FunctionPathAgent] function_response=%s" % (function_response))
                messages.append({ "tool_call_id": tool_call.id, "role": "tool", "content": function_response })
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            messages.append(response)
        return self.build_analysis_path()
        

    
if __name__ == "__main__":
    path_analyzer = DeepSeekPathAnalyzer()
    current_function_info = analysis_operators.find_current_function("tif_read.c:1421")
    var_info = {
        "var_name": "tif_rawdata",
        "var_type": "local_var",
        "arg_index": 20
    }
    alter_prompt = "You are looking for potential MemoryLeak memory issues related to the memory allocated at tif_read.c:1421. This issue is considered to occur if upon reaching the end of the function, the memory has become unreachable and can never be freed."
    model_name = "deepseek-chat"
    client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
    function_path_agent = FunctionPathAgent(current_function_info, var_info, start_location="tif_read.c:1421", previous_analysis_path_list=[], alter_prompt=alter_prompt, client=client, model_name=model_name)
    return_location_list = function_path_agent.analysis_function_paths()
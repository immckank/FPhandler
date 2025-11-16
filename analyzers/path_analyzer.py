import os
import json
import logging
import copy
from tracemalloc import start
from collections import defaultdict

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
    describe_return_locations_desc_path,
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

# BUG :
# tool_call name=complete_path arguments={
    # "path_id": "0", 
    # "classification": "Transferred", 
    # "reason": "The memory pointed to by &data is conceptually transferred to TIFFVSetField through the variable argument mechanism. Although not a direct assignment in the source code, the memory ownership is transferred to the callee functions when TIFFSetField is called successfully. Based on the previous path analysis context, successful calls to TIFFSetField result in the callee taking ownership of the memory.", 
    # "source_location": "tif_dir.c:812", 
    # "code_line": "status = TIFFVSetField(tif, tag, ap);", 
    # "arg": "ap"
# }

class PathAnalyzerModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis")
        self.result_logger = setup_logger(log_type="result")
        self.global_variables = []
        self.memcached_callee_functions = []
        self.memcached_call_sites = []
        self.analysis_path_list = []
        self.analysis_path_registry = {}
        self.analysis_path_groups = {}
        self.analysis_path_group_members = defaultdict(set)
    
    def create_function_path_agent(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt):
        representative_path, path_group = self._resolve_previous_path_context(previous_analysis_path_list)
        return FunctionPathAgent(
            current_function_info,
            var_info,
            start_location,
            representative_path,
            alter_prompt,
            previous_path_group=path_group,
        )
    
    def check_analysis_path_completeness(self):
        # 取出每个分析路径的最后一个元素
        for analysis_path in self.analysis_path_list:
            last_function_analysis_path = analysis_path[-1]
            if last_function_analysis_path["classification"] == "done":
                continue
            else:
                return False
        return True

    def _generate_analysis_path_id(self, path):
        if not path:
            return None
        last_item = path[-1]
        if "analysis_path_id" in last_item and last_item["analysis_path_id"]:
            return last_item["analysis_path_id"]
        tags = []
        if "path_tag_sequence" in last_item and last_item["path_tag_sequence"]:
            tags = last_item["path_tag_sequence"]
        else:
            for idx, item in enumerate(path):
                tag = item.get("path_tag")
                if not tag:
                    function_name = item.get("function_name", "unknown")
                    tag = f"{function_name}@{idx + 1}"
                tags.append(tag)
        analysis_path_id = "/".join(tags)
        last_item["analysis_path_id"] = analysis_path_id
        last_item["path_tag_sequence"] = tags
        return analysis_path_id

    def _path_signature(self, path):
        signature = []
        for item in path:
            var_name = None
            if isinstance(item, dict):
                var_info = item.get("var_info")
                if isinstance(var_info, dict):
                    var_name = var_info.get("var_name")
            signature.append(
                (
                    item.get("function_name"),
                    item.get("classification"),
                    var_name,
                )
            )
        return tuple(signature)

    def _register_analysis_paths(self, new_paths, replace=False):
        if replace:
            self.analysis_path_list = []
            self.analysis_path_registry.clear()
            self.analysis_path_groups.clear()
            self.analysis_path_group_members.clear()
        for path in new_paths or []:
            if not path:
                continue
            path_id = self._generate_analysis_path_id(path)
            self.analysis_path_registry[path_id] = path
            signature = self._path_signature(path)
            canonical_id = self.analysis_path_groups.get(signature)
            if canonical_id is None:
                self.analysis_path_groups[signature] = path_id
                self.analysis_path_group_members[path_id].add(path_id)
                self.analysis_path_list.append(path)
            else:
                self.analysis_path_group_members[canonical_id].add(path_id)
        if new_paths:
            self._debug_log_cluster_state(new_paths, action="register")

    def _deregister_analysis_path(self, path):
        if not path:
            return
        try:
            self.analysis_path_list.remove(path)
        except ValueError:
            pass
        path_id = self._generate_analysis_path_id(path)
        if not path_id:
            return
        signature = self._path_signature(path)
        self.analysis_path_registry.pop(path_id, None)
        canonical_id = self.analysis_path_groups.get(signature)
        if canonical_id == path_id:
            member_ids = self.analysis_path_group_members.pop(path_id, set())
            member_ids.discard(path_id)
            self.analysis_path_groups.pop(signature, None)
            promoted_id = None
            promoted_path = None
            while member_ids:
                candidate_id = member_ids.pop()
                candidate_path = self.analysis_path_registry.get(candidate_id)
                if candidate_path:
                    promoted_id = candidate_id
                    promoted_path = candidate_path
                    break
            if promoted_id:
                remaining_aliases = member_ids.copy()
                remaining_aliases.add(promoted_id)
                self.analysis_path_groups[signature] = promoted_id
                self.analysis_path_group_members[promoted_id] = remaining_aliases
                if promoted_path not in self.analysis_path_list:
                    self.analysis_path_list.append(promoted_path)
            else:
                for alias_id in member_ids:
                    self.analysis_path_registry.pop(alias_id, None)
        else:
            members = self.analysis_path_group_members.get(canonical_id)
            if members and path_id in members:
                members.remove(path_id)
        self._debug_log_cluster_state([path], action="deregister")

    def _debug_log_cluster_state(self, paths, action="update"):
        if not paths:
            return
        cluster_snapshot = []
        for path in paths:
            if not path:
                continue
            path_id = self._generate_analysis_path_id(path)
            signature = self._path_signature(path)
            canonical_id = self.analysis_path_groups.get(signature, path_id)
            member_ids = list(self.analysis_path_group_members.get(canonical_id, []))
            cluster_snapshot.append({
                "path_id": path_id,
                "signature": signature,
                "canonical_id": canonical_id,
                "members": member_ids,
                "path_length": len(path),
            })
        try:
            snapshot_json = json.dumps(cluster_snapshot, ensure_ascii=False)
        except Exception:
            snapshot_json = str(cluster_snapshot)
        print(f"[PathAnalyzerModel] cluster_state action={action} snapshot={snapshot_json}")

    def _get_equivalent_path_group_for_path(self, path):
        group = {
            "canonical_id": None,
            "path_ids": [],
            "paths": [],
            "representative_path": copy.deepcopy(path) if path else [],
        }
        if not path or not isinstance(path, list):
            return group
        signature = self._path_signature(path)
        path_id = None
        if path and isinstance(path[-1], dict):
            path_id = path[-1].get("analysis_path_id")
        if not path_id:
            path_copy = copy.deepcopy(path)
            path_id = self._generate_analysis_path_id(path_copy)
        canonical_id = self.analysis_path_groups.get(signature, path_id)
        member_ids = list(self.analysis_path_group_members.get(canonical_id, set()))
        if canonical_id and canonical_id not in member_ids:
            member_ids.insert(0, canonical_id)
        if not member_ids and canonical_id:
            member_ids.append(canonical_id)
        collected_paths = []
        for member_id in member_ids:
            stored_path = self.analysis_path_registry.get(member_id)
            if stored_path:
                collected_paths.append(copy.deepcopy(stored_path))
        if not collected_paths:
            collected_paths.append(copy.deepcopy(path))
        representative_path = copy.deepcopy(collected_paths[0]) if collected_paths else copy.deepcopy(path)
        group.update(
            {
                "canonical_id": canonical_id,
                "path_ids": member_ids,
                "paths": collected_paths,
                "representative_path": representative_path,
            }
        )
        return group

    def _resolve_previous_path_context(self, previous_analysis_data):
        empty_group = {
            "canonical_id": None,
            "path_ids": [],
            "paths": [],
            "representative_path": [],
        }
        if not previous_analysis_data:
            return [], empty_group
        if isinstance(previous_analysis_data, list):
            if not previous_analysis_data:
                return [], empty_group
            first_element = previous_analysis_data[0]
            if isinstance(first_element, dict):
                group = self._get_equivalent_path_group_for_path(previous_analysis_data)
                representative = copy.deepcopy(group.get("representative_path", previous_analysis_data))
                return representative, group
            if isinstance(first_element, list):
                aggregated_ids = set()
                aggregated_paths = {}
                representative_path = []
                canonical_id = None
                for candidate_path in previous_analysis_data:
                    if not candidate_path:
                        continue
                    group = self._get_equivalent_path_group_for_path(candidate_path)
                    for pid in group.get("path_ids", []):
                        if pid:
                            aggregated_ids.add(pid)
                    for candidate in group.get("paths", []):
                        if not candidate:
                            continue
                        pid = candidate[-1].get("analysis_path_id") if isinstance(candidate[-1], dict) else None
                        if not pid:
                            candidate_copy = copy.deepcopy(candidate)
                            pid = self._generate_analysis_path_id(candidate_copy)
                            candidate = candidate_copy
                        if pid not in aggregated_paths:
                            aggregated_paths[pid] = copy.deepcopy(candidate)
                    if not representative_path:
                        representative_path = copy.deepcopy(group.get("representative_path") or candidate_path)
                    if canonical_id is None:
                        canonical_id = group.get("canonical_id")
                if canonical_id is None and representative_path:
                    if representative_path and isinstance(representative_path[-1], dict):
                        canonical_id = representative_path[-1].get("analysis_path_id")
                return representative_path, {
                    "canonical_id": canonical_id,
                    "path_ids": list(aggregated_ids),
                    "paths": list(aggregated_paths.values()),
                    "representative_path": representative_path,
                }
        return [], empty_group

    def build_lvar_gep_info(self, start_loc):
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        lvar_store_cl = analysis_operators.get_var_store_cl(start_loc, variable_name)
        lvar_analysis_info = analysis_operators.analysis_lvar(start_loc, lvar_store_cl)
        gep_info = lvar_analysis_info["gep_info"]
        if gep_info["gep_cl"]:
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
                "offset": 0,
                "baseobj_type": gep_info["baseobj_type"],
            }
        return gep_info
    
    def check_lvar_param(self, start_loc):
        variable_name = extract_lhs_variable(find_code_line(start_loc))
        lvar_store_cl = analysis_operators.get_var_store_cl(start_loc, variable_name)
        lvar_analysis_info = analysis_operators.analysis_lvar(start_loc, lvar_store_cl)
        return lvar_analysis_info["is_lvar_param"]
    
    def responseForAlter(self, alter : memory_defect.MemoryLeak):
        self.analysis_path_list = []
        self.analysis_path_registry.clear()
        self.analysis_path_groups.clear()
        self.analysis_path_group_members.clear()
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
            function_analysis_path["path_tag"] = f"{current_function_info['function_name']}@0"
            function_analysis_path["path_tag_sequence"] = [function_analysis_path["path_tag"]]
            function_analysis_path["analysis_path_id"] = function_analysis_path["path_tag"]
            function_analysis_path["depends_on"] = None
            self._register_analysis_paths([[function_analysis_path]], replace=not self.analysis_path_list)
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
                        function_path_agent = self.create_function_path_agent(caller_function, var_info, call_site_location, self.analysis_path_list, self.alter_prompt)
                        new_paths = function_path_agent.analysis_function_paths()
                        self._register_analysis_paths(new_paths)
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
            new_paths = function_path_agent.analysis_function_paths()
            self._register_analysis_paths(new_paths, replace=not self.analysis_path_list)
        
        print(f"analysis_path_list: {self.analysis_path_list}")
        
        while True:
            if self.check_analysis_path_completeness():
                break
            for analysis_path in self.analysis_path_list.copy():
                print(f"analysis_path: {analysis_path}")
                previous_analysis_path = copy.deepcopy(analysis_path)
                last_function_analysis_path = analysis_path[-1]
                if last_function_analysis_path["classification"] == "done":
                    print(f"analysis_path: {analysis_path} terminated with done")
                    continue
                last_function_name = last_function_analysis_path["function_name"]
                last_var_info = last_function_analysis_path["var_info"]
                if last_function_analysis_path["classification"] == "Returned to caller":
                    # 返回给调用者
                    # 这里有两种情况 要么是作为参数被转移 要么是真的作为返回值被转移了
                    # 以前只处理了后者
                    # 寻找所有的调用位置
                    call_sites = analysis_operators.find_callers(last_function_name)
                    self._deregister_analysis_path(analysis_path)
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
                                    done_item = copy.deepcopy(current_analysis_path[-1]) if current_analysis_path else {}
                                    if isinstance(done_item, dict):
                                        done_item["classification"] = "done"
                                    else:
                                        done_item = {"classification": "done"}
                                    current_analysis_path.append(done_item)
                                    self._register_analysis_paths([current_analysis_path])
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
                                    caller_function_info = analysis_operators.find_current_function(call_site_loc)
                                function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site_loc, previous_analysis_path, self.alter_prompt)
                                new_paths = function_path_agent.analysis_function_paths()
                                self._register_analysis_paths(new_paths)
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
                        # 这里表明是formal arg
                        # 查询上一个函数的参数列表 找var info中的名字是第几个参数
                        last_function_info = analysis_operators.find_function_body(last_function_name)
                        formal_arg_name_list = get_formal_arg_names(find_code_line(f"{last_function_info['filename']}:{last_function_info['start_line']}"))["args"]
                        last_function_varargs = get_formal_arg_names(find_code_line(f"{last_function_info['filename']}:{last_function_info['start_line']}"))["has_varargs"]
                        var_name = last_var_info["var_name"]
                        if var_name in formal_arg_name_list:
                            arg_index = formal_arg_name_list.index(var_name)
                            # 表明在调用者那边作为了第arg_index个参数
                            for call_site in call_sites:
                                call_site_loc = call_site["location"]
                                call_site_code = call_site["code"]
                                caller_function_info = analysis_operators.find_current_function(call_site_loc)
                                if call_site_loc in self.memcached_call_sites:
                                    continue
                                else:
                                    self.memcached_call_sites.append(call_site_loc)
                                # 对应第arg_index个参数
                                var_info = {
                                    "var_name": get_actual_arg_names(call_site_code, last_function_name)[arg_index],
                                    "var_type": "actual_arg",
                                    "arg_index": arg_index,
                                    "gep_info": last_var_info["gep_info"]
                                }
                                current_analysis_path = copy.deepcopy(previous_analysis_path)
                                function_path_agent = self.create_function_path_agent(caller_function_info, var_info, call_site_loc, current_analysis_path, self.alter_prompt)
                                new_paths = function_path_agent.analysis_function_paths()
                                self._register_analysis_paths(new_paths)
                        else:
                            gep_type = last_var_info["gep_info"]["gep_type"]
                            if gep_type == "baseobj":
                                # baseobj 转移了 但是没有在实参列表中出现
                                # 这种情况比较少见 暂时认为leak
                                self.analysis_logger.error(f"Baseobj {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                self.result_logger.error(f"Baseobj {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
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
                                        new_paths = function_path_agent.analysis_function_paths()
                                        self._register_analysis_paths(new_paths)
                                else:
                                    # 这个地方有问题 log相关信息
                                    self.analysis_logger.error(f"Cannot find baseobj name {baseobj_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    self.result_logger.error(f"Cannot find baseobj name {baseobj_name} in formal arg name list {formal_arg_name_list} for {var_name} at {last_function_info['filename']}:{last_function_info['start_line']}")
                                    return analysis_path
                            else:
                                self.analysis_logger.error(f"{previous_analysis_path}")
                                self.analysis_logger.error(f"{last_function_analysis_path}")
                                self.analysis_logger.error(f"Non-struct variable {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                self.result_logger.error(f"Non-struct variable {var_name} at {last_function_info['filename']}:{last_function_info['start_line']} is not found in formal arg name list {formal_arg_name_list}")
                                return analysis_path
                    continue
                elif last_function_analysis_path["classification"] == "Handled by callee":
                    # 被调用者处理
                    callee_function_name = last_function_analysis_path["arg"]
                    callee_function_info = analysis_operators.find_function_body(callee_function_name)
                    print(f"callee_function_info: {callee_function_info}")
                    call_location = last_function_analysis_path["source_location"]
                    call_code = find_code_line(call_location)
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
                    
                    print(f"call_arg_index: {call_arg_index}")
                    # 实际上就是追踪formal arg / index为call_arg_index / function info为callee_function_info / 
                    if callee_function_name == "free":
                        analysis_path.append({"classification": "done"})
                        self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                        self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee")
                    else:
                        formal_arg_info = get_formal_arg_names(find_code_line(f"{callee_function_info["filename"]}:{callee_function_info["start_line"]}"))
                        if {
                            "function_name": callee_function_name,
                            "arg_index": call_arg_index
                        } in self.memcached_callee_functions:
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Handled by callee and cached")
                            analysis_path.append({"classification": "done"})
                            continue
                        if len(formal_arg_info["args"]) == 1:
                            self.memcached_callee_functions.append({
                                "function_name": callee_function_name,
                                "arg_index": call_arg_index
                            })
                        if formal_arg_info["has_varargs"]:
                            var_info = {
                                "var_name": last_var_info["var_name"],
                                "var_type": "formal_arg",
                                "arg_index": call_arg_index,
                                "gep_info": formal_arg_gep_info
                            }
                        else:
                            var_info = {
                                "var_name": formal_arg_info["args"][call_arg_index],
                                "var_type": "formal_arg",
                                "arg_index": call_arg_index,
                                "gep_info": formal_arg_gep_info
                            }
                        function_path_agent = self.create_function_path_agent(callee_function_info, var_info, callee_function_info["start_line"], previous_analysis_path, self.alter_prompt)
                        self._deregister_analysis_path(analysis_path)
                        new_paths = function_path_agent.analysis_function_paths()
                        self._register_analysis_paths(new_paths)
                    continue
                elif last_function_analysis_path["classification"] == "Transferred":
                    # transfer function : transfer发生的函数
                    # caller function : 调用transfer function的函数
                    transfer_location = last_function_analysis_path["source_location"]
                    transfer_function_info = analysis_operators.find_current_function(transfer_location)
                    var_name = last_function_analysis_path["arg"]
                    if last_function_analysis_path["source_location"] is None:
                        # 表明这是在处理可变长参数 var组装应该怎么办呢
                        # TODO
                        var_info = {
                            "var_name": var_name,
                            "var_type": "local_var",
                            "arg_index": -1,
                            "gep_info": {
                                "gep_type": "not_struct",
                                "baseobj_name": var_name,
                                "member_name" : None,
                                "offset": 0,
                                "baseobj_type":"ptr"
                            }
                        }
                        function_path_agent = self.create_function_path_agent(transfer_function_info, var_info, transfer_location, previous_analysis_path, self.alter_prompt)
                        new_paths = function_path_agent.analysis_function_paths()
                        self._register_analysis_paths(new_paths)
                        continue
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
                        self._deregister_analysis_path(analysis_path)
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
                            new_paths = function_path_agent.analysis_function_paths()
                            self._register_analysis_paths(new_paths)
                    else:
                        # 转移给了局部变量 或 全局变量
                        if var_name in self.global_variables:
                            analysis_path.append({"classification": "done"})
                            self.analysis_logger.info(f"Analysis path {analysis_path} terminated with Transferred and global variable")
                            self.result_logger.info(f"Analysis path {analysis_path} terminated with Transferred and global variable")
                            continue
                        else:
                            self._deregister_analysis_path(analysis_path)
                            var_info = {
                                "var_name": var_name,
                                "var_type": "local_var",
                                "arg_index": analysis_operators.get_var_store_cl(transfer_location, var_name),
                                "gep_info": self.build_lvar_gep_info(transfer_location),
                            }
                            function_path_agent = self.create_function_path_agent(transfer_function_info, var_info, transfer_location, previous_analysis_path, self.alter_prompt)
                            new_paths = function_path_agent.analysis_function_paths()
                            self._register_analysis_paths(new_paths)
                    continue
                else: 
                    # Unreachable # NullPointer
                    # 删除原来的path
                    current_analysis_path = copy.deepcopy(previous_analysis_path)
                    self._deregister_analysis_path(analysis_path)
                    done_item = copy.deepcopy(current_analysis_path[-1]) if current_analysis_path else {}
                    if isinstance(done_item, dict):
                        done_item["classification"] = "done"
                    else:
                        done_item = {"classification": "done"}
                    current_analysis_path.append(done_item)
                    self._register_analysis_paths([current_analysis_path])
                    print(f"analysis_path_list: {self.analysis_path_list}")
                    continue
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
        representative_path, path_group = self._resolve_previous_path_context(previous_analysis_path_list)
        return FunctionPathAgent(
            current_function_info,
            var_info,
            start_location,
            representative_path,
            alter_prompt,
            client=self.client,
            model_name=self.model_name,
            previous_path_group=path_group,
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
    
    def create_function_path_agent(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt):
        representative_path, path_group = self._resolve_previous_path_context(previous_analysis_path_list)
        return FunctionPathAgent(
            current_function_info,
            var_info,
            start_location,
            representative_path,
            alter_prompt,
            client=self.client,
            model_name=self.model_name,
            previous_path_group=path_group,
        )


class FunctionPathAgent():
    _path_tag_counter = defaultdict(int)

    @classmethod
    def allocate_path_tag(cls, function_name):
        cls._path_tag_counter[function_name] += 1
        return f"{function_name}@{cls._path_tag_counter[function_name]}"

    def __init__(self, current_function_info, var_info, start_location, previous_analysis_path_list, alter_prompt, client=None, model_name=None, previous_path_group=None):
        self.path_idx = 0
        self.client = client
        self.model_name = model_name
        self.alter_prompt = alter_prompt
        self.current_function_info = current_function_info
        self.var_info = var_info
        if isinstance(previous_path_group, dict):
            self.previous_path_group = copy.deepcopy(previous_path_group)
        else:
            self.previous_path_group = {
                "canonical_id": None,
                "path_ids": [],
                "paths": [],
                "representative_path": copy.deepcopy(previous_analysis_path_list)
                if isinstance(previous_analysis_path_list, list)
                else [],
            }
        representative_path = []
        if self.previous_path_group.get("representative_path"):
            representative_path = copy.deepcopy(self.previous_path_group["representative_path"])
        elif isinstance(previous_analysis_path_list, list):
            representative_path = copy.deepcopy(previous_analysis_path_list)
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
        self.previous_analysis_path_list = representative_path or []
        self.previous_path_group["representative_path"] = copy.deepcopy(self.previous_analysis_path_list)
        self.previous_equivalent_path_ids = self.previous_path_group.get("path_ids", [])
        self.parent_path_tags = []
        self.parent_analysis_path_id = None
        if isinstance(self.previous_analysis_path_list, list) and self.previous_analysis_path_list:
            try:
                self.parent_path_tags = copy.deepcopy(
                    self.previous_analysis_path_list[-1].get("path_tag_sequence", [])
                )
            except Exception:
                self.parent_path_tags = []
            self.parent_analysis_path_id = self.previous_analysis_path_list[-1].get("analysis_path_id")
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
            "describe_return_locations": self.describe_return_locations_Tool,
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
        self._debug_previous_paths()
    
    # 管理函数
    def build_analysis_path(self):
        # previous_analysis_path_list: [{function1 analysis path}, {function2 analysis path}, ...]
        # self.function_analysis_path_list: [{current function analysis path1}, {current function analysis path2}, ...]
        # build -> [[previous analysis path, current function analysis path1], [previous analysis path, current function analysis path2], ...]
        new_analysis_path_list = []
        for current_function_analysis_path in self.function_analysis_path_list:
            if current_function_analysis_path["status"] != "completed":
                continue
            depends_on_value = current_function_analysis_path.get("depends_on", self.parent_analysis_path_id)
            if isinstance(depends_on_value, (list, tuple, set)):
                depends_on_list = [str(d) for d in depends_on_value if d not in (None, "")]
            else:
                depends_on_list = [depends_on_value]
            if not depends_on_list:
                depends_on_list = [self.parent_analysis_path_id]
            for depends_on in depends_on_list:
                new_analysis_path = copy.deepcopy(self.previous_analysis_path_list)
                path_item = copy.deepcopy(current_function_analysis_path["path_items"])
                path_tag = self.allocate_path_tag(self.current_function_info["function_name"])
                path_item["path_tag"] = path_tag
                path_tag_sequence = self.parent_path_tags + [path_tag]
                path_item["path_tag_sequence"] = path_tag_sequence
                path_item["analysis_path_id"] = "/".join(path_tag_sequence)
                path_item["depends_on"] = depends_on
                new_analysis_path.append(path_item)
                new_analysis_path_list.append(new_analysis_path)
        print(
            "[FunctionPathAgent] build_analysis_path new_analysis_path_list=%d"
            % (len(new_analysis_path_list))
        )
        print(f"new_analysis_path_list: {new_analysis_path_list}")
        return new_analysis_path_list

    def _code_line_matcher(self, source_location, code_line):
        code_line_number = source_location.split(":")[1]
        code_line_number = int(code_line_number)
        for i in range(-2, 3):
            if code_line_number + i > 0:
                candidate_code_line = find_code_line(f"{source_location.split(':')[0]}:{code_line_number + i}")
                if candidate_code_line == code_line or candidate_code_line == code_line.strip():
                    return f"{source_location.split(':')[0]}:{code_line_number + i}"
        return {"error": f"mismatched code line number for {source_location} : {find_code_line(source_location)} and {code_line}"}

    def _safe_find_code_line(self, location):
        if not location:
            return ""
        try:
            return find_code_line(location)
        except Exception:
            return ""

    def _format_previous_analysis_paths(self):
        path_group_paths = []
        path_ids = []
        if isinstance(self.previous_path_group, dict):
            path_group_paths = self.previous_path_group.get("paths") or []
            path_ids = self.previous_path_group.get("path_ids") or []
        if not path_group_paths:
            return ""
        prompt_lines = ["Here are several analysis paths leading to the current function:"]
        # 需要被分为同一类的路径 一定有相同的函数和分类
        # 只需要取group当中的一个
        one_path = path_group_paths[-1]
        # 在某个函数 内的某个var 在某个return点处 被分类为{}
        # 所有的路径都需要满足如下的条件
        prompt_lines.append(f"all the paths should satisfy the following conditions:")
        for function_analysis_path in one_path:
            # the memory of {var_name} at {start_location} is classified as {classification} inside {function_name} and returned at {return_location}
            var_name = function_analysis_path.get("var_name", "the target value")
            start_location = function_analysis_path.get("start_location")
            start_line_code = self._safe_find_code_line(start_location)
            classification = function_analysis_path.get("classification", "unknown state")
            function_name = function_analysis_path.get("function_name", "unknown function")
            return_location = function_analysis_path.get("return_location")
            return_line_code = self._safe_find_code_line(return_location)
            prompt_lines.append(f"- the memory of {var_name} at {start_location} : {start_line_code} is classified as {classification} inside {function_name} and returned at {return_location} : {return_line_code}")
        # 但不同路径的conditions不一样
        # 不同路径的要满足的conditions如下
        prompt_lines.append(f"different paths should satisfy the following conditions:")
        for idx, paths in enumerate(path_group_paths):
            path_id = path_ids[idx] if idx < len(path_ids) else f"path_{idx + 1}"
            conditions_description = f" - path {path_id} should satisfy the following conditions:"
            for path in paths:
                # 在函数{function_name}当中需要满足条件{conditions}
                conditions_description += f" - in function {path.get('function_name')} : {path.get('conditions')}"
            conditions_description += "\n"
            prompt_lines.append(conditions_description)
        prompt_lines.append("Please continue the analysis from these path contexts.")
        return "\n".join(prompt_lines) + "\n"

    def _debug_previous_paths(self):
        group_paths = []
        path_ids = []
        if isinstance(self.previous_path_group, dict):
            group_paths = self.previous_path_group.get("paths") or []
            path_ids = self.previous_path_group.get("path_ids") or []
        if group_paths:
            summary_items = []
            for idx, path in enumerate(group_paths[:5], 1):
                if not path or not isinstance(path, list):
                    continue
                tail = path[-1] if isinstance(path[-1], dict) else {}
                summary_items.append(
                    {
                        "index": idx,
                        "analysis_path_id": tail.get("analysis_path_id"),
                        "depends_on": tail.get("depends_on"),
                        "classification": tail.get("classification"),
                        "length": len(path),
                    }
                )
            try:
                summary_json = json.dumps(
                    {"path_ids": path_ids, "paths": summary_items}, ensure_ascii=False
                )
            except Exception:
                summary_json = str({"path_ids": path_ids, "paths": summary_items})
            print(f"[FunctionPathAgent] previous path summary={summary_json}")
            return
        if not isinstance(self.previous_analysis_path_list, list) or not self.previous_analysis_path_list:
            print("[FunctionPathAgent] previous paths: none")
            return
        summary_items = []
        for idx, item in enumerate(self.previous_analysis_path_list):
            if not isinstance(item, dict):
                summary_items.append({"index": idx, "type": type(item).__name__})
                continue
            summary_items.append({
                "index": idx,
                "function": item.get("function_name"),
                "classification": item.get("classification"),
                "analysis_path_id": item.get("analysis_path_id"),
                "path_tag": item.get("path_tag"),
                "path_tag_sequence": item.get("path_tag_sequence"),
            })
            if len(summary_items) >= 5:
                break
        try:
            summary_json = json.dumps(summary_items, ensure_ascii=False)
        except Exception:
            summary_json = str(summary_items)
        print(f"[FunctionPathAgent] previous path summary={summary_json}")

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
    
    def check_previous_path_completeness(self):
        if not isinstance(self.previous_equivalent_path_ids, list):
            self.previous_equivalent_path_ids = []
        target_ids = [str(pid) for pid in self.previous_equivalent_path_ids if pid]
        if not target_ids:
            return []

        referenced_ids = set()

        def _collect_dep(dep_value):
            if dep_value is None:
                return
            if isinstance(dep_value, (list, tuple, set)):
                for item in dep_value:
                    _collect_dep(item)
                return
            dep_str = str(dep_value).strip()
            if dep_str:
                referenced_ids.add(dep_str)

        for path in self.function_analysis_path_list:
            _collect_dep(path.get("depends_on"))
            path_items = path.get("path_items")
            if isinstance(path_items, dict):
                _collect_dep(path_items.get("depends_on"))

        missing_ids = [pid for pid in target_ids if pid not in referenced_ids]
        if missing_ids:
            print(
                f"[FunctionPathAgent] previous paths missing depends_on references: {missing_ids}"
            )
        return missing_ids
    
    def describe_return_locations(self):
        if not self.return_location_list:
            return "No return locations recorded for current function."
        descriptions = []
        for return_info in self.return_location_list:
            return_location = return_info["return_location"]
            possible_path_number = return_info.get("possible_path_number", 0)
            possible_path_list = return_info.get("possible_path_list") or []
            try:
                code_line = find_code_line(return_location)
            except Exception:
                code_line = ""
            related_paths = [
                path for path in self.function_analysis_path_list
                if path["return_location"] == return_location and path["status"] != "deleted"
            ]
            completed_paths = [path for path in related_paths if path["status"] == "completed"]
            active_paths = [path for path in related_paths if path["status"] == "active"]
            if (
                possible_path_number == 0
                and not possible_path_list
                and not related_paths
            ):
                continue
            descriptions.append(
                f"- return {return_location}: \"{code_line.strip()}\"; "
                f"expected_paths={possible_path_number}, "
                f"completed_paths={return_info['completed_path_number']} "
                f"(active={len(active_paths)}, total_created={len(related_paths)})"
            )
        if not descriptions:
            return "No matching return locations."
        return "\n".join(descriptions)
    
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
    
    def describe_return_locations_Tool(self):
        return {"return_locations": self.describe_return_locations()}
        
    def _normalize_depends_on(self, depends_on):
        if depends_on is None:
            return self.parent_analysis_path_id
        if isinstance(depends_on, (list, tuple, set)):
            normalized = [str(item) for item in depends_on if item is not None and str(item).strip() != ""]
            if not normalized:
                return self.parent_analysis_path_id
            if len(normalized) == 1:
                return normalized[0]
            return normalized
        depends_on = str(depends_on).strip()
        if not depends_on:
            return self.parent_analysis_path_id
        return depends_on

    # path相关
    def create_path_Tool(self, return_location, description, path_id=None, depends_on=None):
        if return_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', return_location):
            return {"error": f"invalid return_location: {return_location}"}
        # 校验return_location是否在return_locations中
        return_location_info = next(filter(lambda x: x["return_location"] == return_location, self.return_location_list), None)
        if return_location_info is None:
            return {"error": f"return_location {return_location} not found in return_locations."}
        path_id = str(self.path_idx)
        self.path_idx += 1
        depends_on = self._normalize_depends_on(depends_on)
        new_path = {
            "path_id": path_id,
            "return_location": return_location,
            "status": "active",
            "path_items": None,
            "description": description,
            "depends_on": depends_on,
        }
        self.function_analysis_path_list.append(new_path)
        print("[FunctionPathAgent] create_path path_id=%s return_location=%s" % (path_id, return_location))
        return new_path

    def _match_path_id_in_sequence(self, path_sequence, target_path_id):
        if not path_sequence or not target_path_id:
            return None
        for item in path_sequence:
            if not isinstance(item, dict):
                continue
            candidate_ids = [
                item.get("analysis_path_id"),
                item.get("path_tag"),
            ]
            path_tag_sequence = item.get("path_tag_sequence")
            if isinstance(path_tag_sequence, (list, tuple)) and path_tag_sequence:
                candidate_ids.append("/".join(path_tag_sequence))
            for candidate in candidate_ids:
                if candidate is None:
                    continue
                if str(candidate) == target_path_id:
                    return item
        return None

    def _query_previous_analysis_path(self, path_id):
        if not path_id:
            return None
        candidate_paths = []
        if isinstance(self.previous_path_group, dict):
            path_group_paths = self.previous_path_group.get("paths") or []
            representative_path = self.previous_path_group.get("representative_path")
            candidate_paths.extend(path_group_paths)
            if representative_path:
                candidate_paths.append(representative_path)
        if not candidate_paths and isinstance(self.previous_analysis_path_list, list) and self.previous_analysis_path_list:
            candidate_paths.append(self.previous_analysis_path_list)
        seen = set()
        for path_sequence in candidate_paths:
            if not path_sequence or not isinstance(path_sequence, list):
                continue
            seq_id = id(path_sequence)
            if seq_id in seen:
                continue
            seen.add(seq_id)
            matched_item = self._match_path_id_in_sequence(path_sequence, path_id)
            if matched_item:
                return {
                    "path_id": path_id,
                    "status": "previous",
                    "path_items": copy.deepcopy(path_sequence),
                    "matched_item": copy.deepcopy(matched_item),
                    "source": "previous_analysis_path",
                }
        return None

    def query_paths_Tool(self, path_id):
        # 暂时过滤掉deleted的path
        path_id = str(path_id)
        path = next(filter(lambda x: x["path_id"] == path_id and x["status"] != "deleted", self.function_analysis_path_list), None)
        if path is None:
            previous_path = self._query_previous_analysis_path(path_id)
            if previous_path:
                return previous_path
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
    def complete_path_Tool(self, path_id, classification, reason, conditions, source_location=None, code_line=None, arg=None):
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
        path_dependency = path.get("depends_on", self.parent_analysis_path_id)
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
                "reason": reason,
            }
            path["path_items"]["depends_on"] = path_dependency
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Transferred":
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Transferred classification"}
            if arg is None:
                return {"error": f"arg is required for Transferred classification to specify which variable the memory was transferred to."}
            source_location = self._code_line_matcher(source_location, code_line)
            if "error" in source_location:
                return {"error": source_location["error"]}
            # 如果当前函数是可变长参数 且当前追踪的变量是对应可变长参数当中的... 那么只需要执行宽松的检验
            formal_arg_info = get_formal_arg_names(find_code_line(f"{self.current_function_info['filename']}:{self.current_function_info["start_line"]}"))
            formal_arg_name_list = formal_arg_info["args"]
            formal_arg_varargs = formal_arg_info["has_varargs"]
            if formal_arg_varargs and self.var_info["var_name"] not in formal_arg_name_list:
                # 我们只需要让模型指定被转移给了哪个参数 从何处开始接管了即可
                path["path_items"] = {
                    "var_info": self.var_info,
                    "start_location": self.start_location,
                    "function_name": self.current_function_info["function_name"],
                    "return_location": return_location,
                    "classification": classification,
                    "source_location": source_location if source_location else self.current_function_info["start_line"],
                    "reason": reason,
                    "conditions": conditions,
                    "arg": arg
                }
                path["path_items"]["depends_on"] = path_dependency
                path["status"] = "completed"
                return_location_info["completed_path_number"] += 1
                return path            
            if self.start_location == source_location:
                return {"error": f"The source location {source_location} is the same as the start location {self.start_location}. Please check if the code line is correct or if the line is a gep or store operation."}
            eq_position_l = analysis_operators.get_eq_position_list(source_location)
            if eq_position_l is None:
                return {"error": f"The code line at {source_location} : {find_code_line(source_location)} has no related store statement. Please check if the code line is correct."}
            matched_arg = False
            for eq_position in eq_position_l:
                code_line = find_code_line(source_location)
                if arg in code_line[:(eq_position-1)] and (self.var_info["var_name"] in code_line[(eq_position-1):]):
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
                "conditions": conditions,
                "arg": arg
            }
            path["path_items"]["depends_on"] = path_dependency
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Returned to caller":
            # TODO 这里还需要匹配gep 如果参数自己 / 参数的baseobj在函数参数列表中被转移也可以
            return_pointer_json = analysis_operators.check_return_pointer(return_location)
            formal_arg_info = get_formal_arg_names(find_code_line(f"{self.current_function_info['filename']}:{self.current_function_info["start_line"]}"))
            formal_arg_name_list = formal_arg_info["args"]
            formal_arg_varargs = formal_arg_info["has_varargs"]
            if return_pointer_json["function_can_return_pointer"] and return_pointer_json["location_has_pointer_operation"]:
                arg = "return_value"
            # 判定变量名是不是直接就在函数的参数列表中
            elif self.var_info["var_name"] in formal_arg_name_list or formal_arg_varargs:
                arg = "formal_arg"
            elif self.var_info["gep_info"]["gep_type"] == "member" and self.var_info["gep_info"]["baseobj_name"] in formal_arg_name_list:
                arg = "formal_arg"
            else:
                return {"error": f"Cannot find the var name {self.var_info['var_name']} in formal arg list: {formal_arg_name_list}. Please check if the code line is correct. You may specify all the possible memory event along the path"}
            path["path_items"] = {
                "var_info": self.var_info,
                "start_location": self.start_location,
                "function_name": self.current_function_info["function_name"],
                "return_location": return_location,
                "classification": classification,
                "source_location": source_location,
                "reason": reason,
                "conditions": conditions,
                "arg": arg
            }
            path["path_items"]["depends_on"] = path_dependency
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        elif classification == "Handled by callee":
            source_location = self._code_line_matcher(source_location, code_line)
            if "error" in source_location:
                return {"error": source_location["error"]}
            if source_location is None or not re.match(r'^[\w/]+\.(c|h):\d+$', source_location):
                return {"error": f"invalid source_location: {source_location}"}
            if code_line is None:
                return {"error": f"code_line is required for Handled by callee classification"}
            if arg is None:
                return {"error": f"arg is required for Handled by callee classification to specify which function was used to release the memory."}
            # TODO 这里还需要匹配gep 如果base变量被转移也可以
            extracted_function_name, arg_index = get_arg_index(code_line, self.var_info["var_name"])
            if extracted_function_name is None or arg_index is None:
                return {"error": f"Cannot find the function name and arg index in the code line at {source_location} : {find_code_line(source_location)} for the arg {self.var_info['var_name']}. You may just give the code line where the transfer happens or check if the code line is correct."}
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
                "conditions": conditions,
                "arg": arg
            }
            path["path_items"]["depends_on"] = path_dependency
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
                "reason": reason,
                "conditions": conditions,
            }
            path["path_items"]["depends_on"] = path_dependency
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
                "reason": reason,
                "conditions": conditions,
            }
            path["path_items"]["depends_on"] = path_dependency
            path["status"] = "completed"
            return_location_info["completed_path_number"] += 1
            return path
        else:
            return {"error": f"unknown classification: {classification}"}
    
    # 维护这个方法来保证在一个函数中生成多个抵达返回位置的路径的分析    
    def analysis_function_paths(self):
        allowed_tools = [
            dump_source_snippet_desc_free, dump_source_line_desc_free, find_current_function_desc_free, find_function_body_desc_free, find_callers_desc_free,
            create_path_desc_path, describe_return_locations_desc_path, complete_path_desc_path, query_paths_desc_path, delete_path_desc_path
        ]
        # 整理所有返回路径 每个返回路径指向一个return位置 一个return位置可能有多个返回路径
        if self.var_info["var_type"] == "formal_arg":
            self.arg_index = self.var_info["arg_index"]
            wappered_return_locations = analysis_operators.get_value_sensitive_arg_icfg_return_path(self.current_function_info["function_name"], self.arg_index)
            var_prompt = f"You are now tracing the memory of {self.var_info['var_name']} in the function {self.current_function_info['function_name']}. The variable is the {self.arg_index + 1}th formal argument of this function."
            # 变长参数依然需要特殊处理
            formal_arg_info = get_formal_arg_names(find_code_line(f"{self.current_function_info['filename']}:{self.current_function_info["start_line"]}"))
            formal_arg_name_list = formal_arg_info["args"]
            formal_arg_varargs = formal_arg_info["has_varargs"]
            if formal_arg_varargs and self.var_info["var_name"] not in formal_arg_name_list:
                var_prompt += f"The current function {self.current_function_info['function_name']} uses variadic arguments (...). You must identify the local variable that receives the tracked data from the argument list. The data flow is now transferred to this local variable."
        elif self.var_info["var_type"] == "actual_arg":    
            self.arg_index = self.var_info["arg_index"]
            wappered_return_locations = analysis_operators.get_value_sensitive_call_arg_icfg_return_path(self.start_location, self.arg_index, self.previous_analysis_path_list[-1]["function_name"])
            var_prompt = f"You are now tracing the memory of {self.var_info['var_name']} in the function {self.current_function_info['function_name']}. The variable is the {self.arg_index + 1}th actual argument used to call {self.previous_analysis_path_list[-1]['function_name']}."
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
        function_prompt = f"The current function name is {self.current_function_info['function_name']}\n"
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
                            passed_source_location_list = []
                            for vfg_node_item in return_location_info['possible_path_list'][i]:
                                if vfg_node_item['location'] not in passed_source_location_list:
                                    passed_source_location_list.append(vfg_node_item['location'])
                                    return_prompt += f"passed code line at {vfg_node_item['location']} : {find_code_line(vfg_node_item['location'])}\n"                
                            print("================================================")
                            print(f"possible_path_list: {return_location_info['possible_path_list'][i]}")
                            print("================================================")
                        else:
                            return_prompt += "basic path\n"
        return_prompt += f"You should only create necessary paths and claim the state of the variable {self.var_info['var_name']} (or the resource it holds) along paths to the return point as following six categories:\n"
        return_prompt += f"The variable is always a null pointer (NullPointer).\n"
        return_prompt += f"Ownership of the memory has been transferred through an assignment to another variable (Transferred), or other forms of transfer.\n"
        return_prompt += f"The memory is returned as return value to the caller or as (part of) an actual argument used to call a function (Returned to caller), only when the var you are tracing is used as return value or a formal argument in current function.\n"
        return_prompt += f"The memory will be handled by the callee (Handled by callee), only when the var you are tracing is used as a actual argument in a function call.\n"
        return_prompt += f"A memory leak has occurred (Leak).\n"
        return_prompt += f"This return point is unreachable (Unreachable), Or, this path is not feasible according to previous conditions.\n"
        return_prompt += "For each potential execution path which is necessary for the analysis, first use create_path to register it after the previous analysis paths (if any), and finalize the judgement with complete_path once you determine the classification. You may query or delete paths using query_paths and delete_path if necessary.\n"
        previous_analysis_path_prompt = self._format_previous_analysis_paths()
        project_prompt = f"You are now working for project {PROJECT_NAME}. {PROJECT_DESC}\n"
        messages = [
            {"role": "system", "content": VALUE_PATH_PROMPT + project_prompt},
            {"role": "user", "content": self.alter_prompt + previous_analysis_path_prompt + var_prompt + function_prompt + return_prompt}
        ] 
        # logmessages
        print("================================================")
        print(f"messages: {messages}")
        print("================================================")
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
                missing_previous_dependencies = self.check_previous_path_completeness()
                if len(incomplete_return_locations) > 0:
                    return_location_details = self.describe_return_locations()
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The return locations {incomplete_return_locations} are not complete. "
                            "Please create path to these return locations.\n"
                            f"{return_location_details}"
                        )
                    })
                    response = self.send_message(messages, allowed_tools)
                    if not response.content:
                        response.content = ""
                    messages.append(response)
                    continue
                if len(missing_previous_dependencies) > 0:
                    messages.append({
                        "role": "user",
                        "content": (
                            "Some previous analysis paths are not referenced via depends_on. "
                            f"Please create or update paths that depend on: {missing_previous_dependencies}."
                            "You can use create_path tool with list of previous path ids to create a new path depends on several similar previous paths."
                        ),
                    })
                    response = self.send_message(messages, allowed_tools)
                    if not response.content:
                        response.content = ""
                    messages.append(response)
                    continue
                if len(incomplete_paths) > 0:
                    messages.append({
                        "role": "user", 
                        "content": (
                            f"The paths {incomplete_paths} are not complete. Please complete or delete these paths."
                        ),
                    })
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

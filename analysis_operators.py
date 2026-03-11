import os
import subprocess
import logging
import sys
import json
import re
from utils import *
from typing import List, Dict, Any, Optional, Set

from command_caller import CommandCaller

import config

PROJECT_ROOT = os.path.abspath(config.PROJECT_ROOT)
BITCODE_PATH = config.BITCODE_PATH

# source_location 格式校验：支持相对路径（如 ../../../dir/file.c:755），后端允许此类输入；
# 规则：冒号仅用于分隔行号；路径任意非空且以 .c / .h / .cpp 结尾
SOURCE_LOCATION_PATTERN = re.compile(r'^[^:]+\.(c|h|cpp):\d+$')


def _strip_error_false(res_json: dict) -> None:
    """Remove error key when false or absent; avoid KeyError on del."""
    if res_json.get("error") is False:
        res_json.pop("error", None)
    elif res_json.get("error"):
        pass  # keep for caller to check
    else:
        res_json.pop("error", None)


def _query_find_function_body_by_location(source_loc) -> Optional[dict]:
    """Build find-function-body-by-location query with fl/ln/cl only."""
    d = normalize_source_loc(source_loc)
    if not d:
        return None
    q = {"command": "find-function-body-by-location", "fl": d["fl"], "ln": int(d["ln"])}
    if d.get("cl") is not None:
        q["cl"] = int(d["cl"])
    return q


def _location_query_payload(source_loc) -> Optional[dict]:
    """fl/ln/cl dict for any command that used to take location string."""
    d = normalize_source_loc(source_loc)
    if not d:
        return None
    out = {"fl": d["fl"], "ln": int(d["ln"])}
    if d.get("cl") is not None:
        out["cl"] = int(d["cl"])
    return out

'''
system function
'''

def set_conclusion(classification: str, reason: str) -> Dict[str, str]:
    """Sets the final conclusion for an alert analysis.

    This function is intended to be called at the end of an analysis to provide a definitive classification and the reasoning behind it.

    Args:
        classification: The classification of the alert, must be one of "FP"
                        (False Positive), "TP" (True Positive), or "UNCERTAIN".
        reason: Summary a detailed explanation for the given classification.

    Returns:
        If the input is invalid, it returns a dictionary with an error message.
    """
    # check if classification in [FP, TP, UNCERTAIN]
    if classification not in ["FP", "TP", "UNCERTAIN"]:
        message = {"error" : "classification must be one of [FP, TP, UNCERTAIN]"}
        return message
    # reason != none
    if reason is None:
        message = {"error" : "reason must not be none"}
        return message
    message = {"classification" : classification, "reason" : reason}
    return message

'''
structure function
'''

def find_callers(function_name: str) -> List[Dict[str, Any]]:
    """Finds all functions that call a given target function.

    Args:
        function_name: The name of the target function to find callers for.

    Returns:
        A list of dictionaries, where each dictionary represents a call site
        and contains the location and the source code of the call.
        Example:
        [{'location': 'proto_text.c:581', 'code': '...'},
         {'location': 'proto_bin.c:602', 'code': '...'}]
        Returns an empty list if no callers are found or an error occurs.
    """
    command_caller = CommandCaller()
    query = {
        "command": "find-all-function-call-sites",
        "name": function_name
    }
    res = command_caller.send_query(query)
    call_sites_list = []
    if res:
        res_json = json.loads(res)
        error = res_json.get("error")
        if error:
            return [{"error": f"error in finding call sites for function {function_name}, plesse check if the name is right. {error}"}]
        _strip_error_false(res_json)
        for call_site in res_json.get("call_sites", []):
            ensure_location_string(call_site)
            loc = call_site.get("location")
            if loc and ":" in loc:
                fl, ln_str = loc.rsplit(":", 1)
                if ln_str.isdigit():
                    call_site["code"] = dump_source_line(fl, int(ln_str))
            elif call_site.get("fl") is not None and call_site.get("ln") is not None:
                call_site["code"] = dump_source_line(call_site["fl"], int(call_site["ln"]))
            call_sites_list.append(call_site)
        return call_sites_list
    return []

# # 暂时不用了
def find_callee(source_location) -> Optional[List[Dict[str, Any]]]:
    """Finds the function body of functions called at a specific source location.

    Args:
        source_location: The source location of the call site, in the format
                         'filename.c:line_number'.

    Returns:
        A list of dictionaries, each representing a callee function, including its
        name, file, line numbers, and full body. Returns None if the location
        is invalid or no callee is found.
        Example:
        [{'function_name': 'callee_func', 'filename': 'a.c', 'start_line': 10,
          'end_line': 20, 'function_body': '...'}]
    """
    if isinstance(source_location, str) and not SOURCE_LOCATION_PATTERN.match(source_location):
        d = parse_source_location_to_fl_ln(source_location)
        if not d:
            logging.error(f"Invalid source location format: {source_location}")
            return None
    command_caller = CommandCaller()
    query = _query_find_function_body_by_location(source_location)
    if not query:
        logging.error(f"Invalid source location: {source_location}")
        return None
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"Error finding callee for {source_location!s}: {error} {res_json}"}
        function_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
        res_json["function_body"] = function_body
        return res_json
    return None

def find_function_body(function_name: str) -> Optional[Dict[str, Any]]:
    """Finds the function body by its name.

    Args:
        function_name: The name of the function to find.

    Returns:
        A dictionary containing the details of the function, including its name,
        file, line numbers, and full body. Returns None if the function is not found.
        Example:
        {'function_name': 'target_func', 'filename': 'a.c', 'start_line': 5,
         'end_line': 25, 'function_body': '...'}
    """
    command_caller = CommandCaller()
    query = {
        "command": "find-function-body-by-name",
        "name": function_name
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"Error finding function body for {function_name}, plesse check if the name is right. {error}"}
        func_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
        res_json["function_body"] = func_body
        return res_json
    return None

def find_current_function(source_location) -> Optional[Dict[str, Any]]:
    """Finds the function in which the given source location exists.

    Args:
        source_location: The source location, in the format 'filename.c:line_number'.

    Returns:
        A dictionary containing the details of the function, including its name,
        file, line numbers, and full body. Returns None if the location is
        invalid or the function is not found.
        Example:
        {'function_name': 'current_func', 'filename': 'a.c', 'start_line': 5,
         'end_line': 25, 'function_body': '...'}
    """
    if isinstance(source_location, str) and not SOURCE_LOCATION_PATTERN.match(source_location):
        if not parse_source_location_to_fl_ln(source_location):
            return {"error": "Invalid source location format, source_location should be in the format 'filename.c:line_number'."}
    command_caller = CommandCaller()
    query = _query_find_function_body_by_location(source_location)
    if not query:
        return {"error": "Invalid source location."}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error")
        if error:
            return {"error": f"Error finding current function for {source_location!s}, check if the location is right."}
        _strip_error_false(res_json)
        func_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
        res_json["function_body"] = func_body
        return res_json
    return {"error": "Unknown error"}

def find_all_callees(function_name: str) -> List[Dict[str, Any]]:
    command_caller = CommandCaller()
    query = {
        "command": "find-all-function-callees",
        "name": function_name
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return [{"error": f"error in finding all callees"}]
        _strip_error_false(res_json)
        return res_json.get("callees", [])
    return []

# 这个函数暂时不用了；后端主流程为 show-return-locations，仅 name
def find_return_locations(function_name: str, source_location: str = None) -> List[Dict[str, Any]]:
    command_caller = CommandCaller()
    query = {"command": "show-return-locations", "name": function_name}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error")
        if error:
            return [{"error": f"error in finding return locations for function {function_name}: {error}"}]
        _strip_error_false(res_json)
        locs = res_json.get("return_locations", [])
        # 若调用方仍传入 source_location，可在 Python 侧过滤（可选）
        if source_location and locs:
            d = normalize_source_loc(source_location)
            if d:
                locs = [
                    x for x in locs
                    if (x.get("fl") or x.get("filename")) == d["fl"] and int(x.get("ln") or x.get("line") or 0) == d["ln"]
                ] or locs
        return locs
    return []

def check_return_pointer(return_location: str) -> Optional[Dict[str, Any]]:
    """Checks if the return location is a pointer.
    Args:
        return_location: The location of the return, in the format 'filename.c:line_number'.
    Returns:
        A dictionary containing the details of the return, including its type and value.
    """
    command_caller = CommandCaller()
    query = {
        "command": "check-return-pointer",
        "location": return_location
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"error in checking return pointer for {return_location}, check if the location is right. {error}"}
        else:
            del res_json["error"]
            return res_json
    return None


'''
structure ctags
'''
# TODO:不一定有用
def ctags_readtags(source_location: str, id_name: str) -> List[str]:
    """Finds all occurrences of a given identifier using ctags.

    This function generates a ctags file for the project if it doesn't exist,
    then searches for all locations of the specified identifier.

    Args:
        source_location: A source location within the project to determine the
                         project path (e.g., 'memcached/items.c:100').
        id_name: The identifier (e.g., variable or function name) to search for.

    Returns:
        A list of source locations in 'filename:line_number' format.
    """
    # ctags实现
    # 在 PROJECT_ROOT 下生成/使用 tags
    project_path = PROJECT_ROOT
    tag_file_path = os.path.join(project_path, "tags")
    if not os.path.exists(tag_file_path):
        # 在项目根目录运行命令生成ctags文件
        print(f"Generating ctags file in {project_path}...")
        subprocess.run(["ctags", "-R", "--fields=+n", "--languages=C,C++", "-f", "tags"], cwd=project_path)
    source_location_list = []
    try:
        with open(tag_file_path, "r") as f:
            for line in f:
                if line.startswith("!_"):
                    continue
                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue
                tag_name = parts[0]
                if tag_name == id_name:
                    file_path = parts[1]
                    line_number = None
                    for field in parts[3:]:
                        if field.startswith('line:'):
                            try:
                                line_number = int(field.split(':')[1])
                                break
                            except (ValueError, IndexError):
                                continue
                    if line_number is None:
                        address = parts[2]
                        match = re.match(r'^(\d+);"', address)
                        if match:
                            line_number = match.group(1)
                    if line_number is not None:
                        res_source_location = f"{file_path}:{line_number}"
                        source_location_list.append(res_source_location)
        return source_location_list
    except FileNotFoundError:
        logging.error(f"Tag file not found: {tag_file_path}")
        return []
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return []

'''
structure variable
'''

# trace lvar base object
def find_base_lvar_def(source_location: str, eq_position: int) -> Optional[Dict[str, Any]]:
    command_caller = CommandCaller()
    payload = _location_query_payload(source_location)
    if not payload:
        return {"error": f"Invalid source_location: {source_location}"}
    query = {"command": "find-base-lvar-def", "eq_position": str(eq_position), **payload}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        print(f"res_json base lvar: {res_json}")
        error = res_json.get("error", None)
        if error:
            return {"error": f"error in finding base lvar def for {source_location}, check if the location and eq_position are right. {error}"}
        return res_json
    return None


# analysis lvar
def analysis_lvar(source_location: str, eq_position: int) -> Optional[List[Dict[str, Any]]]:
    '''
    {
        "command":"analysis-lvar",
        "eq_position":6,
        "gep_info":{
            "baseobj_type":"ptr",
            "gep_cl":null,
            "gep_type":"not_struct",
            "offset":0
            },
        "icfg_node_id":46283,
        "is_lvar_baseobj_param":false,
        "is_lvar_param":false,
        "is_member_access":false,
        "is_struct_lvalue":false,
        "lhs_pag_id":54312,
        "location":"tif_dirwrite.c:1707",
        "store_ir":"  store i32 %85, ptr %18, align 4, !dbg !12247",
        "success":true
    }
    '''
    command_caller = CommandCaller()
    payload = _location_query_payload(source_location)
    if not payload:
        logging.error(f"Invalid source location: {source_location}")
        return None
    query = {"command": "analysis-lvar", "eq_position": str(eq_position), **payload}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error analyzing lvar at {source_location} with eq_position {eq_position}: {error}")
            return None
        else:
            return res_json
    return None

'''
path condition
'''

def get_value_sensitive_lvar_icfg_return_path(start_location: str, eq_position: int) -> Optional[List[Dict[str, Any]]]:
    if not SOURCE_LOCATION_PATTERN.match(start_location) and not parse_source_location_to_fl_ln(start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    command_caller = CommandCaller()
    payload = _location_query_payload(start_location)
    if not payload:
        return None
    query = {"command": "find-lvalue-path-inside", "eq_position": str(eq_position), **payload}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding value sensitive icfg return path for {start_location} with eq_position {eq_position}: {error}")
            return None
        _strip_error_false(res_json)
        return res_json.get("return_locations", [])
    return None

def get_value_sensitive_arg_icfg_return_path(function_name: str, index: int) -> Optional[List[Dict[str, Any]]]:
    command_caller = CommandCaller()
    query = {
        "command" : "find-arg-value-path-inside",
        "function_name" : function_name,
        "arg_index" : str(index)
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding value sensitive arg icfg return path for {function_name} with index {index}: {error}")
            return None
        _strip_error_false(res_json)
        return res_json.get("return_locations", [])
    return None

def get_value_sensitive_call_arg_icfg_return_path(location: str, arg_index: int, callee_function_name: str = "") -> Optional[List[Dict[str, Any]]]:
    command_caller = CommandCaller()
    payload = _location_query_payload(location)
    if not payload:
        logging.error(f"Invalid location: {location}")
        return None
    query = {
        "command": "find-call-arg-value-path-inside",
        "arg_index": str(arg_index),
        "callee_function_name": callee_function_name,
        **payload,
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding value sensitive call arg icfg return path at {location} with index {arg_index}: {error}")
            logging.error(f"query: {query}")
            logging.error(f"res: {res}")
            return None
        _strip_error_false(res_json)
        return res_json.get("return_locations", [])
    return None

def get_shortest_path_cond(start_location: str, target_location: str):
    """path-cond-func via send_query only (no subprocess CLI args)."""
    if not SOURCE_LOCATION_PATTERN.match(start_location) and not parse_source_location_to_fl_ln(start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    if not SOURCE_LOCATION_PATTERN.match(target_location) and not parse_source_location_to_fl_ln(target_location):
        logging.error(f"Invalid source location format: {target_location}")
        return None
    command_caller = CommandCaller()
    query = {
        "command": "path-cond-func",
        "start_location": start_location,
        "target_location": target_location,
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding shortest path condition for {start_location} to {target_location}: {error}")
            return None
        _strip_error_false(res_json)
        paths = res_json.get("paths", [])
        shortest_path = None
        min_length = float("inf")
        for path in paths:
            events = path.get("events", [])
            if len(events) < min_length:
                min_length = len(events)
                shortest_path = path
        if shortest_path:
            events = shortest_path.get("events", [])
            for event in events:
                ensure_location_string(event)
                loc = event.get("location")
                if loc and ":" in loc:
                    fl, ln_str = loc.rsplit(":", 1)
                    if ln_str.isdigit():
                        event["code"] = dump_source_line(fl, int(ln_str))
            return shortest_path.get("events", [])
    return None
    
# get_path_cond_func
# 找到startline到targetline所有路径 收集路径中未返回的调用及条件分支
# return 
def get_path_cond_func_(start_location: str, start_code: str, target_location: str, target_code: str) -> Optional[List[Dict[str, Any]]]:
    """Finds all paths between a start and target location, collecting information
    about function calls and conditional branches along the way.

    Args:
        start_location: The start source location, in 'filename.c:line_number' format.
        start_code: The source code of the start location.
        target_location: The target source location, in 'filename.c:line_number' format.
        target_code: The source code of the target location.

    Returns:
        A list of dictionaries, where each dictionary represents a path. Each path
        contains a list of 'events' (function calls or conditions) with their
        location and source code. Returns None if an error occurs or no paths are found.
        Example:
        [
            {
                "events": [
                    {"type": "condition", "location": "restart.c:80", "code": "if (foo)"},
                    {"type": "call", "location": "restart.c:85", "code": "bar()"}
                ]
            }
        ]
    """
    if not SOURCE_LOCATION_PATTERN.match(start_location):
        return {"error": "Invalid source location format, source_location should be in the format 'filename.c:line_number'."}
    if not SOURCE_LOCATION_PATTERN.match(target_location):
        return {"error": "Invalid source location format, source_location should be in the format 'filename.c:line_number'."}
    # 检索start_location处的代码
    found = True
    if not start_code.strip() in find_code_line(start_location).strip():
        found = False
        line_number = start_location.split(":")[1]
        line_number = int(line_number)
        for i in range(max(1, line_number-5), line_number+5):
            loc = f"{start_location.split(':')[0]}:{i}"
            code_line = find_code_line(loc)
            if start_code.strip() in code_line.strip():
                line_number = i
                start_location = f"{start_location.split(':')[0]}:{line_number}"
                found = True
                break
    if not found:
        return {"error": "wrong line number for start_location, please check line number or start code."}
    found = True
    if not target_code.strip() in find_code_line(target_location).strip():
        found = False
        line_number = target_location.split(":")[1]
        line_number = int(line_number)
        for i in range(max(1, line_number-5), line_number+5):
            
            loc = f"{target_location.split(':')[0]}:{i}"
            code_line = find_code_line(loc)
            print(code_line)
            if target_code.strip() in code_line.strip():
                line_number = i
                target_location = f"{target_location.split(':')[0]}:{line_number}"
                found = True
                break
    if not found:
        return {"error": "wrong line number for target_location, please check line number or start code."}
    print(f"start loc : {start_location}")
    command_caller = CommandCaller()
    query = {
        "command": "path-cond-func",
        "start_location": start_location,
        "target_location": target_location,
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            print(res)
            return {"error" : f"Error finding path condition function for {start_location} to {target_location}, check if the location is right."}
        _strip_error_false(res_json)
        paths = res_json.get("paths", [])
        for path in paths:
            events = path.get("events", [])
            for event in events:
                ensure_location_string(event)
                loc = event.get("location")
                if loc:
                    event["code"] = find_code_line(loc)
        return res_json.get("paths", [])
    return None

# get_path_cond_func
# 找到startline到targetline所有路径 收集路径中未返回的调用及条件分支
# return 
def get_path_cond_func(start_location: str, target_location: str) -> Optional[List[Dict[str, Any]]]:
    """Finds all paths between a start and target location, collecting information
    about function calls and conditional branches along the way.

    Args:
        start_location: The start source location, in 'filename.c:line_number' format.
        target_location: The target source location, in 'filename.c:line_number' format.

    Returns:
        A list of dictionaries, where each dictionary represents a path. Each path
        contains a list of 'events' (function calls or conditions) with their
        location and source code. Returns None if an error occurs or no paths are found.
        Example:
        [
            {
                "events": [
                    {"type": "condition", "location": "restart.c:80", "code": "if (foo)"},
                    {"type": "call", "location": "restart.c:85", "code": "bar()"}
                ]
            }
        ]
    """
    if not SOURCE_LOCATION_PATTERN.match(start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    if not SOURCE_LOCATION_PATTERN.match(target_location):
        logging.error(f"Invalid source location format: {target_location}")
        return None
    command_caller = CommandCaller()
    query = {
        "command": "path-cond-func",
        "start_location": start_location,
        "target_location": target_location,
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error")
        if error:
            logging.error(f"Error finding path condition function for {start_location} to {target_location}: {error}")
            return None
        _strip_error_false(res_json)
        paths = res_json.get("paths", [])
        for path in paths:
            events = path.get("events", [])
            for event in events:
                ensure_location_string(event)
                loc = event.get("location")
                if loc and ":" in loc:
                    fl, ln_str = loc.rsplit(":", 1)
                    if ln_str.isdigit():
                        event["code"] = dump_source_line(fl, int(ln_str))
        return res_json.get("paths", [])
    return None

# check_always_implying、
# 检测两个表达式是否总是蕴含关系
# exp1  exp2
# return: bool
def check_always_implying(exp1: str, exp2: str) -> Optional[bool]:
    # 基于求解器来实现
    return None

'''
bound
'''


# check_le
# 检测两个表达式exp1 <= exp2是否恒成立
# exp1  exp2
# return: bool
def check_le(exp1: str, exp2: str) -> Optional[bool]:
    # 基于求解器来实现
    return None

'''
context
'''

# dump_source_snippet
# 按行号寻找指定代码片段
def dump_source_snippet(file_name: str, start_line: int, end_line: int) -> Optional[str]:
    """Dumps a snippet of source code from a file between the given line numbers.

    Args:
        file_name: The name of the file relative to the project root.
        start_line: The starting line number (inclusive).
        end_line: The ending line number (inclusive).

    Returns:
        The source code snippet as a string, or None if the file cannot be read
        or line numbers are out of range.
    """
    file_path = find_file_path(file_name) 
    if not file_path: return "No such file, please check filename."
    try:
        file_path = os.path.join(PROJECT_ROOT, file_path)
        with open(file_path, "r") as f:
            lines = f.readlines()
            return "".join(lines[int(start_line) - 1:int(end_line)])
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except IndexError:
        return f"Line numbers out of range for file {file_path}"

def dump_source_line(file_name: str, line_number: int) -> Optional[str]:
    """Dumps a single line of source code from a file.

    Args:
        file_name: The name of the file relative to the project root.
        line_number: The line number to retrieve.

    Returns:
        The content of the specified line as a string, or None if an error occurs.
    """
    file_path = find_file_path(file_name)
    if not file_path: return "No such file, please check filename."
    file_path = os.path.join(PROJECT_ROOT, file_path)
    snippet = dump_source_snippet(file_name, line_number, line_number)
    return snippet.strip() if snippet else "The line number is invalid or out of range for the file."

def get_eq_position_list(source_location: str) -> Optional[List[int]]:
    command_caller = CommandCaller()
    payload = _location_query_payload(source_location)
    if not payload:
        return None
    query = {"command": "find-store-cl", **payload}
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding eq position list for {source_location}: {error}")
            return None
        else:
            return res_json.get("store_cl", [])
    return None

def get_gep_position_list(source_location: str) -> Optional[List[int]]:
    
    return None

def check_lvar_gep(source_location: str, eq_position: int):
    # 找到所有左值的gep信息
    # 给出 
    # 1. 左值是否是结构体变量
    # 2. 如果是 给出baseobj的类型名 从llvm指令中提取
    # 3. 如果是 给出偏移量 从llvm指令中提取
    
    return None
    

def get_var_store_cl(source_location: str, var_name: str) -> Optional[List[Dict[str, Any]]]:
    eq_position_list = get_eq_position_list(source_location)
    original_code_line = find_code_line(source_location, strip_whitespace=False)
    if not eq_position_list:
        return None
    for eq_position in eq_position_list:
        if var_name in original_code_line[:eq_position]:
            return eq_position
    return None

if __name__ == '__main__':
    # print(dump_source_snippet("slabs_automove.c", 1, 50))
    # {'start_location': 'items.c:1557', 'start_code': 'calloc(1, sizeof(struct crawler_expired_data))', 
    # 'target_location': 'items.c:1629', 'target_code': 'free(cdata)'}
    #1556     struct crawler_expired_data *cdata =
    #1557 calloc(1, sizeof(struct crawler_expired_data));
    #1630     free(cdata);
    # print(dump_source_snippet("crypto/x509v3/v3_prn.c", 69, 136))
    print(dump_source_snippet("crypto/x509/x_crl.c", 82, 146))
            
    # print(get_path_cond_func_(start_location="items.c:1557", start_code="struct",
    #                           target_location="items.c:1629", target_code="free(cdata)"))
    # # printFunctionCallSites(icfg, "stats_prefix_record_get");
    # print(find_callers("stats_prefix_record_get"))
    # # printCalleeFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_callee("items.c:499"))
    # print(type(find_callee("stats_prefix.c:118")))
    # # printFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_current_function("tiff_jpeg.c:798"))
    # print(get_shortest_path_cond("restart.c:76", "restart.c:121"))
    # print(dump_source_snippet("tif_dirread.c", 2310, 2330))
    # print(find_callers("EVP_CIPHER_CTX_free"))
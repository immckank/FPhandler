import os
import subprocess
import logging
import sys
import json
import re
from typing import List, Dict, Any, Optional


from command_caller import CommandCaller

import config

PUT_ROOT_PATH = config.PUT_ROOT_PATH
PROJECT_NAME = config.PROJECT_NAME

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
    res = command_caller.call_graph_reader_with_args(
        f"-find-call-sites={function_name}",
        os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc")
    )
    call_sites_list = []
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding callers for {function_name}: {error}")
        else:
            # 删除error属性
            del res_json["error"]
            # {'call_sites': [{'location': 'proto_text.c:581'}, {'location': 'proto_bin.c:602'}]}
            # 为每个call_site添加code属性
            for call_site in res_json.get("call_sites", []):
                call_site["code"] = dump_source_line(call_site["location"].split(":")[0], call_site["location"].split(":")[1])
                call_sites_list.append(call_site)
            return call_sites_list
    return []

def find_callee(source_location: str) -> Optional[List[Dict[str, Any]]]:
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
    # 基于LLVM来实现不要使用基于文本的查找
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.c:\d+$', source_location) and not re.match(r'^[\w/]+\.h:\d+$', source_location):
        logging.error(f"Invalid source location format: {source_location}")
        return None
    # 如果以项目名称开头 去掉项目名
    if source_location.startswith(PROJECT_NAME + "/"):
        source_location = source_location[len(PROJECT_NAME) + 1:]
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-find-callee-body={source_location}",
        os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding callee for {source_location}: {error} {res_json}")
        else:
            # 删除error属性
            del res_json["error"]
            callee_functions = res_json.get("callee_functions", [])
            for func in callee_functions:
                func_body = dump_source_snippet(func["filename"], func['start_line'], func['end_line'])
                # 为func添加func_body属性
                func["function_body"] = func_body
            return callee_functions
    return None

def find_current_function(source_location: str) -> Optional[Dict[str, Any]]:
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
    # 基于LLVM来实现不要使用基于文本的查找
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.c:\d+$', source_location) and not re.match(r'^[\w/]+\.h:\d+$', source_location):
        logging.error(f"Invalid source location format: {source_location}")
        return None
    # 如果以项目名称开头 去掉项目名
    if source_location.startswith(PROJECT_NAME + "/"):
        source_location = source_location[len(PROJECT_NAME) + 1:]
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-find-function-body={source_location}", 
        os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding current function for {source_location}: {error}")
        else:
            # 删除error属性
            del res_json["error"]
            func_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
            # 为func添加func_body属性
            res_json["function_body"] = func_body
            return res_json
    return None

'''
structure ctags
'''

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
    project_path = os.path.join(PUT_ROOT_PATH, source_location.split(":")[0].split("/")[0])
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

# find_var_definitions
# 找到指定变量所有被定义的位置
# return: list < str >
def find_var_definitions(source_location: str, var_name: str) -> List[str]:
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return []

# find_var_decl
# 找到变量声明的位置
# return: str: 'memcached/slab_automove.c:37'
def find_var_decl(source_location: str, var_name: str) -> Optional[str]:
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None


'''
path condition
'''

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
    if not re.match(r'^[\w/]+\.c:\d+$', start_location) and not re.match(r'^[\w/]+\.h:\d+$', start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    if not re.match(r'^[\w/]+\.c:\d+$', target_location) and not re.match(r'^[\w/]+\.h:\d+$', target_location):
        logging.error(f"Invalid source location format: {target_location}")
        return None
    if start_location.startswith(PROJECT_NAME + "/"):
        start_location = start_location[len(PROJECT_NAME) + 1:]
    if target_location.startswith(PROJECT_NAME + "/"):
        target_location = target_location[len(PROJECT_NAME) + 1:]
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-path-cond-func-start={start_location}",
        f"-path-cond-func-end={target_location}",
        os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding path condition function for {start_location} to {target_location}: {error}")
            return None
        else:
            del res_json["error"]
            paths = res_json.get("paths", [])
            for path in paths:
                events = path.get("events", [])
                for event in events:
                    location = event.get("location", None)
                    if location:
                        event["code"] = dump_source_line(location.split(":")[0], location.split(":")[1])
            return res_json.get("paths", [])
    return None

# get_path_constraint
# 找到当前source_location的路径约束条件的表达式
# return: str
def get_path_constraint(source_location: str) -> Optional[str]:
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
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
    file_path = os.path.join(PUT_ROOT_PATH, PROJECT_NAME, file_name)
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
            return "".join(lines[int(start_line) - 1:int(end_line)])
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except IndexError:
        logging.error(f"Line numbers out of range for file {file_path}")
        return None

def dump_source_line(file_name: str, line_number: int) -> Optional[str]:
    """Dumps a single line of source code from a file.

    Args:
        file_name: The name of the file relative to the project root.
        line_number: The line number to retrieve.

    Returns:
        The content of the specified line as a string, or None if an error occurs.
    """
    file_path = os.path.join(PUT_ROOT_PATH, PROJECT_NAME, file_name)
    snippet = dump_source_snippet(file_name, line_number, line_number)
    return snippet.strip() if snippet else None

if __name__ == '__main__':
    # # printFunctionCallSites(icfg, "stats_prefix_record_get");
    # print(find_callers("stats_prefix_record_get"))
    # # printCalleeFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_callee("stats_prefix.c:118"))
    # print(type(find_callee("stats_prefix.c:118")))
    # # printFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_current_function("stats_prefix.c:118"))
    get_path_cond_func("restart.c:76", "restart.c:121")
import os
import subprocess
import logging
import sys
import json
import re
from utils import *
from typing import List, Dict, Any, Optional, Set

def _configure_libclang():
    """Finds and configures the path to libclang."""
    # Option 1: From environment variable
    libclang_path = os.environ.get('LIBCLANG_PATH')
    if libclang_path and os.path.exists(libclang_path):
        cindex.Config.set_library_file(libclang_path)
        return True

    # Option 2: Look in a project-specific path
    # Assuming SVFmemplus is a sibling directory to the project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    svf_lib_path = os.path.abspath(os.path.join(project_root, '..', 'SVFmemplus', 'build', 'lib', 'libclang.so'))
    if os.path.exists(svf_lib_path):
        cindex.Config.set_library_file(svf_lib_path)
        return True

    return False

try:
    from clang import cindex
    from clang.cindex import CursorKind
    libclang_available = _configure_libclang()
except ImportError:
    libclang_available = False
    logging.warning("libclang not available. Some features will be disabled.")


from command_caller import CommandCaller

import config

PUT_ROOT_PATH = config.PUT_ROOT_PATH
PROJECT_NAME = config.PROJECT_NAME
PUT_NAME = config.PUT_NAME

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
    res = command_caller.call_graph_reader_with_args(
        f"-find-call-sites={function_name}",
        os.path.join(PUT_ROOT_PATH, f"{PUT_NAME}.bc")
    )
    call_sites_list = []
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return [{"error": f"error in finding call sites for function {function_name}, plesse check if the name is right. {error}"}]
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

# 暂时不用了
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
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
        logging.error(f"Invalid source location format: {source_location}")
        return None
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-find-callee-body={source_location}",
        os.path.join(PUT_ROOT_PATH, f"{PUT_NAME}.bc")
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
    res = command_caller.call_graph_reader_with_args(
        f"-find-body-by-name={function_name}",
        os.path.join(PUT_ROOT_PATH, f"{PUT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"Error finding function body for {function_name}, plesse check if the name is right. {error}"}
        func_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
        res_json["function_body"] = func_body
        return res_json
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
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
        return {"error": "Invalid source location format, source_location should be in the format 'filename.c:line_number'."}
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-find-function-body={source_location}", 
        os.path.join(PUT_ROOT_PATH, f"{PUT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"Error finding current function for {source_location}, check if the location is right."}
        else:
            # 删除error属性
            del res_json["error"]
            func_body = dump_source_snippet(res_json["filename"], res_json['start_line'], res_json['end_line'])
            # 为func添加func_body属性
            res_json["function_body"] = func_body
            return res_json
    return {"error": "Unknown error"}

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
def find_var_definitions(source_location: str, var_name: str) -> List[Dict[str, str]]:
    """Finds all definitions of a given variable across the project.

    This function searches for variable definitions, which are locations where
    memory is actually allocated for the variable (i.e., not 'extern' declarations).
    The search starts from the given source location and expands to the entire project
    if necessary.

    Args:
        source_location: The source location to provide context, in the format 'filename.c:line_number'.
        var_name: The name of the variable to find definitions for.

    Returns:
        A list of dictionaries, where each dictionary represents a definition
        site and contains its location and source code. Returns an empty list
        if no definitions are found.
        Example: [{'location': 'items.c:100', 'code': 'item *it = item_alloc(...);'}]
    """
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
        return []
    if not libclang_available:
        return []
    
    try:
        file_name = source_location.split(":")[0]
        file_path = find_file_path(file_name)
        full_file_path = os.path.join(PUT_ROOT_PATH, file_path)
        
        # 检查文件是否存在
        if not os.path.exists(full_file_path):
            # logging.error(f"文件不存在: {full_file_path}")
            return []
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        # 传递适当的解析选项，确保包含的文件也被解析
        args = ['-I' + PUT_ROOT_PATH]
        translation_unit = index.parse(full_file_path, args=args)
        
        if not translation_unit:
            # logging.error("无法创建 translation unit")
            return []
            
        # 检查诊断信息
        diagnostics = list(translation_unit.diagnostics)
        error_count = 0
        for diag in diagnostics:
            if diag.severity >= cindex.Diagnostic.Error:  # Error or fatal
                error_count += 1
                # logging.warning(f"解析警告/错误: {diag.spelling} (级别: {diag.severity})")
        
        # if error_count > 0:
            # logging.warning(f"存在 {error_count} 个严重错误，可能影响分析结果")
            
        # 在整个翻译单元中查找变量定义
        definitions = []
        processed_locations: Set[str] = set()

        def _add_definition(cursor):
            location = cursor.location
            if not location.file:
                return

            file_name = location.file.name
            if file_name.startswith(os.path.abspath(PUT_ROOT_PATH)):
                file_name = os.path.relpath(file_name, PUT_ROOT_PATH)
            if file_name.startswith(PROJECT_NAME + "/"):
                file_name = file_name[len(PROJECT_NAME) + 1:]
            
            location_str = f"{file_name}:{location.line}"
            if location_str not in processed_locations:
                code = dump_source_line(file_name, location.line)
                definitions.append({"location": location_str, "code": code})
                processed_locations.add(location_str)
        
        def find_variable_definitions(cursor, var_name):
            # 检查是否为变量声明
            if cursor.kind == CursorKind.VAR_DECL and cursor.spelling == var_name:
                # is_definition() 检查这是否是一个定义而不是一个前向声明
                # 对于变量，如果它不是 extern 并且有存储空间，它就是定义。
                if cursor.is_definition():
                    _add_definition(cursor)
            
            # 递归遍历子节点
            for child in cursor.get_children():
                find_variable_definitions(child, var_name)
        
        find_variable_definitions(translation_unit.cursor, var_name)
        
        # 总是遍历整个项目以查找所有可能的定义，而不仅仅是在找不到时才查找
        if True: # Kept for logical structure, can be removed.
            # 遍历整个PUT目录寻找.c文件
            put_path = os.path.abspath(PUT_ROOT_PATH)
            put_path = os.path.join(put_path, PROJECT_NAME)
            for root, dirs, files in os.walk(put_path):
                # 排除一些不必要的目录
                dirs[:] = [d for d in dirs if d not in ['.git', '.github', 't', 'scripts', 'doc', 'devtools', 'm4', 'vendor']
                            and not os.path.abspath(os.path.join(root, d)).startswith('/usr/include')
                            and not os.path.abspath(os.path.join(root, d)).startswith('/usr/local/include')]
                
                for file in files:
                    if file.endswith('.c'):
                        full_path = os.path.join(root, file)
                        # 避免重复解析原始文件
                        if os.path.abspath(full_path) == os.path.abspath(full_file_path):
                            continue
                        
                        try:
                            tu = index.parse(full_path, args=['-I' + PUT_ROOT_PATH, '-std=c99'])
                            find_variable_definitions(tu.cursor, var_name)
                        except Exception as e:
                            # 如果解析某个文件失败，继续尝试其他文件
                            # logging.warning(f"解析文件 {full_path} 时出错: {e}")
                            continue
        
        return definitions
    except Exception as e:
        # logging.error(f"Error in find_var_definitions: {e}")
        # import traceback
        # logging.error(traceback.format_exc())
        return []

# find_var_decl
# 找到变量声明的位置
# return: str: 'slab_automove.c:37'
def find_var_decl(source_location: str, var_name: str) -> List[Dict[str, str]]:
    """Finds all declarations of a given identifier across the project.

    This function searches for all declaration sites of an identifier, which can
    include variables, functions, structs, typedefs, enums, and macros.
    The search starts from the given source location and expands to the entire project.

    Args:
        source_location: A source location within the project to provide
                         context, in format 'filename.c:line_number'.
        var_name: The name of the identifier to find declarations for.

    Returns:
        A list of dictionaries, where each dictionary represents a declaration
        site and contains its location and source code. Returns an empty list
        if no declarations are found.
        Example: [{'location': 'items.h:50', 'code': 'extern unsigned int total_items;'}]
    """
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
        return []
    if not libclang_available:
        return []
    try:
        file_name = source_location.split(":")[0]
        file_path = find_file_path(file_name)
        full_file_path = os.path.join(PUT_ROOT_PATH, file_path)
        
        # 检查文件是否真的存在
        if not os.path.exists(full_file_path):
            # logging.error(f"File does not exist: {full_file_path}")
            return []
        
        # 使用libclang解析文件，它会自动处理包含的头文件
        index = cindex.Index.create()
        
        # 尝试添加更多编译参数以提高解析成功率
        args = ['-I' + PUT_ROOT_PATH]
        translation_unit = index.parse(full_file_path, args=args)
        
        if not translation_unit:
            # logging.error("Failed to create translation unit")
            return []
            
        declarations: List[Dict[str, str]] = []
        processed_locations: Set[str] = set()

        # 在整个翻译单元中查找变量声明（包括包含的头文件）
        def find_declarations_in_cursor(cursor, var_name):
            # 支持多种声明类型
            supported_kinds = [
                CursorKind.VAR_DECL,        # 变量声明
                CursorKind.STRUCT_DECL,     # 结构体声明
                CursorKind.TYPEDEF_DECL,    # typedef声明
                CursorKind.FUNCTION_DECL,   # 函数声明
                CursorKind.ENUM_DECL,       # 枚举声明
                CursorKind.ENUM_CONSTANT_DECL,  # 枚举常量声明
                CursorKind.MACRO_DEFINITION     # 宏定义
            ]
            
            if cursor.kind in supported_kinds and cursor.spelling == var_name:
                location = cursor.location
                if location.file:
                    # 返回格式: 'filename:line_number'
                    # 使用实际的文件名而不是原始的file_path
                    file_name = location.file.name
                    # 移除PUT_ROOT_PATH前缀以保持一致性
                    if file_name.startswith(os.path.abspath(PUT_ROOT_PATH)):
                        file_name = os.path.relpath(file_name, PUT_ROOT_PATH)
                    # 如果以project name开头删掉project name
                    if file_name.startswith(PROJECT_NAME + "/"):
                        file_name = file_name[len(PROJECT_NAME) + 1:]
                    location_str = f"{file_name}:{location.line}"
                    if location_str not in processed_locations:
                        code = dump_source_line(file_name, location.line)
                        declarations.append({"location": location_str, "code": code})
                        processed_locations.add(location_str)
            
            # 递归遍历子节点
            for child in cursor.get_children():
                find_declarations_in_cursor(child, var_name)
        
        find_declarations_in_cursor(translation_unit.cursor, var_name)
        
        # 在整个项目中查找
        put_path = os.path.abspath(PUT_ROOT_PATH)
        put_path = os.path.join(put_path, PROJECT_NAME)
        processed_files: Set[str] = {os.path.abspath(full_file_path)}

        for root, dirs, files in os.walk(put_path):
            # 排除一些不必要的目录
            dirs[:] = [d for d in dirs if d not in ['.git', '.github', 't', 'scripts', 'doc', 'devtools', 'm4', 'vendor']]
            
            for file in files:
                if file.endswith(('.c', '.cpp', '.h')):
                    current_file_path = os.path.join(root, file)
                    abs_current_path = os.path.abspath(current_file_path)
                    # 避免重复解析原始文件
                    if abs_current_path in processed_files:
                        continue
                    
                    processed_files.add(abs_current_path)
                    try:
                        tu = index.parse(current_file_path, args=args)
                        find_declarations_in_cursor(tu.cursor, var_name)
                    except Exception:
                        continue
        return declarations
    except Exception as e:
        # logging.error(f"Error in find_var_decl: {e}", exc_info=True)
        return []


'''
path condition
'''

# TODO: 注释说明
def get_shortest_path_cond(start_location: str, target_location: str):
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', target_location):
        logging.error(f"Invalid source location format: {target_location}")
        return None
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader_with_args(
        f"-path-cond-func-start={start_location}",
        f"-path-cond-func-end={target_location}",
        os.path.join(PUT_ROOT_PATH, f"{PUT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding shortest path condition for {start_location} to {target_location}: {error}")
            return None
        else:
            del res_json["error"]
            paths = res_json.get("paths", [])
            # 找到最短的路径
            shortest_path = None
            min_length = float('inf')
            for path in paths:
                events = path.get("events", [])
                if len(events) < min_length:
                    min_length = len(events)
                    shortest_path = path
            
            if shortest_path:
                events = shortest_path.get("events", [])
                for event in events:
                    location = event.get("location", None)
                    if location:
                        event["code"] = dump_source_line(location.split(":")[0], location.split(":")[1])
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
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', start_location):
        return {"error": "Invalid source location format, source_location should be in the format 'filename.c:line_number'."}
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', target_location):
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
    res = command_caller.call_graph_reader_with_args(
        f"-path-cond-func-start={start_location}",
        f"-path-cond-func-end={target_location}",
        os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc")
    )
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            print(res)
            return {"error" : f"Error finding path condition function for {start_location} to {target_location}, check if the location is right."}
        else:
            del res_json["error"]
            paths = res_json.get("paths", [])
            for path in paths:
                events = path.get("events", [])
                for event in events:
                    location = event.get("location", None)
                    if location:
                        event["code"] = find_code_line(location)
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
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', target_location):
        logging.error(f"Invalid source location format: {target_location}")
        return None
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
        file_path = os.path.join(PUT_ROOT_PATH, file_path)
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
    file_path = os.path.join(PUT_ROOT_PATH, file_path)
    snippet = dump_source_snippet(file_name, line_number, line_number)
    return snippet.strip() if snippet else "The line number is invalid or out of range for the file."

if __name__ == '__main__':
    # print(dump_source_snippet("slabs_automove.c", 1, 50))
    # {'start_location': 'items.c:1557', 'start_code': 'calloc(1, sizeof(struct crawler_expired_data))', 
    # 'target_location': 'items.c:1629', 'target_code': 'free(cdata)'}
    #1556     struct crawler_expired_data *cdata =
    #1557 calloc(1, sizeof(struct crawler_expired_data));
    #1630     free(cdata);

    # print(get_path_cond_func_(start_location="items.c:1557", start_code="struct",
    #                           target_location="items.c:1629", target_code="free(cdata)"))
    # # printFunctionCallSites(icfg, "stats_prefix_record_get");
    # print(find_callers("stats_prefix_record_get"))
    # # printCalleeFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_callee("items.c:499"))
    # print(type(find_callee("stats_prefix.c:118")))
    # # printFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_current_function("stats_prefix.c:118"))
    # print(get_shortest_path_cond("restart.c:76", "restart.c:121"))
    # print(find_var_definitions("memcached.c:18", "total_prefix_size"))
    pass        
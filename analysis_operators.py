import os
import subprocess
import logging
import sys
import json
import re
import utils
from utils import *
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from collections import defaultdict

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
    if not _configure_libclang():
        # Python 包已找到，但底层的共享库未配置成功
        logging.warning("libclang Python bindings found, but the libclang shared library could not be configured. "
                        "Please ensure LLVM/Clang is installed and LIBCLANG_PATH is set correctly. "
                        "Features requiring libclang will be disabled.")
        libclang_available = False
    else:
        libclang_available = True
except ImportError:
    libclang_available = False
    logging.warning("libclang not available. Some features will be disabled.")
    # Python包本身未找到
    logging.warning("Python package for libclang not found. Please run 'pip install libclang'. "
                    "Features requiring libclang will be disabled.")

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

class Category(str, Enum):
    NullPointer = "NullPointer"
    Unreachable = "Unreachable"
    HandledByCallee = "HandledByCallee"
    ReturnedAsReturnValue = "ReturnedAsReturnValue"
    ReturnedAsPointerParameter = "ReturnedAsPointerParameter"
    Leaked = "Leaked"


def _normalize_source_location(selector: Dict[str, Any]) -> Optional[str]:
    """
    Accepts one of:
      - selector['source_location'] == 'file.c:123'
      - selector['file_path'] + selector['line']
    """
    if not isinstance(selector, dict):
        return None
    sl = selector.get("source_location")
    if isinstance(sl, str) and re.match(r'^[\w/]+\.(c|h|cpp):\d+$', sl):
        return sl
    file_path = selector.get("file_path")
    line = selector.get("line")
    if isinstance(file_path, str) and isinstance(line, int):
        return f"{file_path}:{line}"
    return None


def validate_source_location(source_location: str, code_line: Optional[str] = None, tolerance: int = 2) -> Dict[str, Any]:
    """
    校验与纠错 source_location。
    - 校验格式 'filename.(c|h|cpp):line'
    - 校验文件与行是否存在
    - 若提供 code_line，允许在 ±tolerance 行内自动纠错，返回修正后的 source_location 与实际代码行
    返回：
      {"ok": True, "source_location": "a.c:120", "code_line": "actual code ..."}
      或 {"error": "reason"}
    """
    if not isinstance(source_location, str) or not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
        return {"error": f"Invalid source_location format: {source_location}"}
    file_name, line_str = source_location.split(":")
    try:
        line_num = int(line_str)
    except Exception:
        return {"error": f"Invalid line number in source_location: {source_location}"}

    # 读取原始行；如果失败，返回错误
    try:
        actual = dump_source_line(file_name, line_num)
    except Exception:
        actual = None
    if not isinstance(actual, str) or actual.startswith("No such file") or actual.startswith("The line number is invalid"):
        return {"error": f"File or line not found for source_location: {source_location}"}

    # 如未提供 code_line，则视为通过
    if not isinstance(code_line, str) or code_line.strip() == "":
        return {"source_location": source_location, "code_line": actual}

    # 允许在 ±tolerance 行内纠错
    if actual.strip() == code_line.strip():
        return {"source_location": source_location, "code_line": actual}

    base = line_num
    for delta in range(-tolerance, tolerance + 1):
        if delta == 0:
            continue
        candidate_line = base + delta
        if candidate_line <= 0:
            continue
        candidate_loc = f"{file_name}:{candidate_line}"
        try:
            cand = dump_source_line(file_name, candidate_line)
        except Exception:
            cand = None
        if isinstance(cand, str) and cand.strip() == code_line.strip():
            return {"source_location": candidate_loc, "code_line": cand}

    return {"error": f"mismatched code line at {source_location}: expected '{code_line.strip()}' but got '{actual.strip()}'"}

def normalize_identifier(expr: str) -> str:
    r"""
    将表达式归一化到基础标识符以便匹配：
    - 去掉外围括号与前导强转 (type)
    - 去掉前导一元运算符 * & + - !
    - 遇到 -> . [ 截断为左侧基变量
    - 提取首个标识符 [A-Za-z_]\w*
    """
    if not isinstance(expr, str):
        return ""
    s = expr.strip()
    # 去外围括号
    changed = True
    while changed and s.startswith("(") and s.endswith(")"):
        changed = False
        inner = s[1:-1].strip()
        if inner and (inner.count("(") == inner.count(")")):
            s = inner
            changed = True
    # 去前导强转
    import re
    cast_pat = re.compile(r'^\(\s*[^)]+\s*\)\s*')
    while True:
        m = cast_pat.match(s)
        if not m:
            break
        s = s[m.end():].lstrip()
    # 去前导一元运算符
    while s and s[0] in "*&+-!":
        s = s[1:].lstrip()
    # 按分隔符截断
    for sep in ["->", ".", "["]:
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
            break
    # 提取第一个标识符
    m = re.search(r'[A-Za-z_]\w*', s)
    return m.group(0) if m else s.strip()

def validate_decision(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    统一 JSON 校验与归一化。
    输入示例：
      {"category":"HandledByCallee","params":{"call":{"source_location":"a.c:100","callee_function_name":"free"},"arg_index":0}}
      {"category":"ReturnedAsPointerParameter","params":{"param_index":1}}
      {"category":"NullPointer"}
    返回：若合法，返回形如 {"ok": True, "category": Category, "params": {...}}；否则 {"error": "..."}。
    """
    if not isinstance(payload, dict):
        return {"error": "decision must be an object"}
    category = payload.get("category")
    try:
        category_enum = Category(category)
    except Exception:
        return {"error": f"unsupported category: {category}"}

    params = payload.get("params")
    normalized: Dict[str, Any] = {"ok": True, "category": category_enum, "params": {}}

    if category_enum == Category.HandledByCallee:
        if not isinstance(params, dict):
            return {"error": "params is required for HandledByCallee"}
        call = params.get("call", {})
        arg_index = params.get("arg_index", None)
        param_name = params.get("param_name", None)
        if not isinstance(call, dict):
            return {"error": "params.call must be an object"}
        source_location = _normalize_source_location(call)
        callee_function_name = call.get("callee_function_name") or call.get("callee_name")
        call_param_name = call.get("param_name", None)
        if not source_location:
            return {"error": "params.call must provide source_location or file_path+line"}
        if arg_index is not None and not isinstance(arg_index, int):
            return {"error": "params.arg_index must be an integer"}
        if not isinstance(callee_function_name, str) or not callee_function_name:
            return {"error": "params.call.callee_function_name is required"}
        normalized["params"] = {
            "source_location": source_location,
            "callee_function_name": callee_function_name,
            "arg_index": arg_index,
            # 可选：参数名冗余校验（0-based 优先，名称用于核验或反推）
            "param_name": param_name or call_param_name,
        }
        return normalized

    if category_enum == Category.ReturnedAsPointerParameter:
        if not isinstance(params, dict):
            return {"error": "params is required for ReturnedAsPointerParameter"}
        param_index = params.get("param_index", None)
        param_name = params.get("param_name", None)
        if param_index is None and param_name is None:
            return {"error": "params.param_index or params.param_name is required"}
        if param_index is not None and not isinstance(param_index, int):
            return {"error": "params.param_index must be an integer"}
        normalized["params"] = {"param_index": param_index, "param_name": param_name}
        return normalized

    # 其它类别不需要 params；如传入，必须为空或为 {}
    if params not in (None, {}, []):
        return {"error": f"category {category} should not provide params"}
    normalized["params"] = {}
    return normalized

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

# # 暂时不用了
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
    query = {
        "command": "find-function-body-by-location",
        "location": source_location
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return {"error": f"Error finding callee for {source_location}: {error} {res_json}"}
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
    query = {
        "command": "find-function-body-by-location",
        "location": source_location
    }
    res = command_caller.send_query(query)
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
        else:
            # 删除error属性
            del res_json["error"]
            return res_json.get("callees", [])
    return []

# 这个函数暂时不用了
def find_return_locations(function_name: str, source_location: str) -> List[Dict[str, Any]]:
    # { "command" : "find-return-locations", "name" : "TIFFFetchNormalTag",  "location" : "tif_dirread.c:4981"}
    command_caller = CommandCaller()
    query = {
        "command": "find-return-locations",
        "name": function_name,
        "location": source_location
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            return [{"error": f"error in finding return locations for function {function_name} at {source_location}, check if the name and location are right. {error}"}]
        else:
            # 删除error属性
            del res_json["error"]
            return res_json.get("return_locations", [])
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


def read_ctag_symbol(symbol_name: str) -> Dict[str, Any]:
    """
    Read ctags entries for a given symbol from the project-wide tags file.

    Args:
        symbol_name: Identifier to look up (function, variable, macro, etc.).

    Returns:
        dict: {
            "symbol": <symbol_name>,
            "entries": [
                {
                    "file": "<relative path>",
                    "line": <int or None>,
                    "location": "<file>:<line>" (if line available),
                    "code": "<source line>" (if resolvable),
                    "metadata": {"kind": "...", ...}
                },
                ...
            ]
        }
        or {"error": "..."} when lookup fails.
    """
    if not symbol_name or not isinstance(symbol_name, str):
        return {"error": "symbol_name must be a non-empty string"}

    tags_path = os.path.join(PUT_ROOT_PATH, PROJECT_NAME, "tags")
    if not os.path.exists(tags_path):
        return {"error": f"ctags index not found at {tags_path}. Run generate_ctags_index() first."}

    entries = []
    try:
        with open(tags_path, "r", encoding="utf-8", errors="ignore") as tag_file:
            for raw_line in tag_file:
                if raw_line.startswith("!_"):
                    continue

                parts = raw_line.rstrip("\n")
                if not parts:
                    continue
                columns = parts.split("\t")
                if len(columns) < 3:
                    continue

                tag_name, file_path, ex_cmd = columns[:3]
                if tag_name != symbol_name:
                    continue

                line_no = None
                metadata: Dict[str, Any] = {}

                for field in columns[3:]:
                    if field.startswith("line:"):
                        try:
                            line_no = int(field.split(":", 1)[1])
                        except ValueError:
                            line_no = None
                    elif ":" in field:
                        key, value = field.split(":", 1)
                        metadata[key] = value

                if line_no is None:
                    match = re.match(r'^(\d+);"', ex_cmd)
                    if match:
                        try:
                            line_no = int(match.group(1))
                        except ValueError:
                            line_no = None

                location = f"{file_path}:{line_no}" if line_no is not None else file_path
                code_line = dump_source_line(file_path, line_no) if line_no is not None else None

                entries.append(
                    {
                        "file": file_path,
                        "line": line_no,
                        "location": location,
                        "code": code_line,
                        "metadata": metadata,
                    }
                )

    except Exception as exc:
        logging.error(f"Failed to read ctags index: {exc}")
        return {"error": f"Failed to read ctags index: {exc}"}

    return {"symbol": symbol_name, "entries": entries}

'''
structure variable
'''

# trace lvar base object
def find_base_lvar_def(source_location: str, eq_position: int) -> Optional[Dict[str, Any]]:
    command_caller = CommandCaller()
    query = {
        "command": "find-base-lvar-def",
        "location": source_location,
        "eq_position": str(eq_position)
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        print(f"res_json base lvar: {res_json}")
        error = res_json.get("error", None)
        if error:
            return {"error": f"error in finding base lvar def for {source_location}, check if the location and eq_position are right. {error}"}
        return res_json
    return None

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


def _parse_function_ast(function_source: str):
    """
    Parse a C function snippet with tree-sitter and return (tree, code_bytes).
    """
    if not hasattr(utils, "_init_tree_sitter"):
        logging.warning("tree-sitter helpers are not available in utils.")
        return None, None
    if not utils._init_tree_sitter():
        logging.warning("tree-sitter is not available; skipping AST-based lookup.")
        return None, None
    parser = getattr(utils, "_c_parser", None)
    if parser is None:
        logging.warning("tree-sitter parser failed to initialize.")
        return None, None

    try:
        code_bytes = function_source.encode("utf8")
    except Exception as exc:
        logging.debug(f"Failed to encode function source for tree-sitter: {exc}")
        return None, None

    try:
        return parser.parse(code_bytes), code_bytes
    except Exception as exc:
        logging.debug(f"tree-sitter failed to parse function source: {exc}")
        return None, code_bytes


def _find_identifier_node(node):
    if node is None:
        return None
    if node.type == "identifier":
        return node
    for child in node.children:
        result = _find_identifier_node(child)
        if result:
            return result
    return None


def _build_type_string(type_node, declarator_node, identifier_node, code_bytes):
    """
    Construct a human readable type string by combining the base type descriptor
    and the declarator prefix (e.g., pointer stars, qualifiers).
    """
    parts: List[str] = []
    if type_node is not None:
        base = code_bytes[type_node.start_byte:type_node.end_byte].decode("utf8").strip()
        if base:
            parts.append(base)
    if declarator_node is not None and identifier_node is not None:
        prefix = code_bytes[declarator_node.start_byte:identifier_node.start_byte].decode("utf8").strip()
        if prefix:
            parts.append(prefix)
    type_str = " ".join(part for part in parts if part).strip()
    type_str = re.sub(r"\s+", " ", type_str)
    return type_str


def _extract_local_var_from_declaration(
    declaration_node,
    target_var: str,
    code_bytes: bytes,
    filename: str,
    function_start_line: int,
):
    if declaration_node is None:
        return None

    candidates = []
    for child in declaration_node.children:
        if child.type == "init_declarator":
            declarator = child.child_by_field_name("declarator") or child
            if declarator:
                candidates.append(declarator)
        elif child.type in {",", ";"}:
            continue
        elif child.type.endswith("declarator") or child.type == "identifier":
            candidates.append(child)

    type_node = declaration_node.child_by_field_name("type")

    for declarator in candidates:
        identifier_node = _find_identifier_node(declarator)
        if not identifier_node:
            continue
        ident = code_bytes[identifier_node.start_byte:identifier_node.end_byte].decode("utf8")
        if ident != target_var:
            continue

        type_string = _build_type_string(type_node, declarator, identifier_node, code_bytes)
        line_no = function_start_line + identifier_node.start_point[0]
        location = f"{filename}:{line_no}"

        try:
            code_line = dump_source_line(filename, line_no)
        except Exception:
            code_line = None

        return {
            "var_name": ident,
            "type": type_string or "",
            "location": location,
            "code_line": code_line,
        }

    return None


def _walk_for_local_declaration(node, *args, **kwargs):
    """
    Depth-first search for declarations containing the target variable.
    """
    if node is None:
        return None

    if node.type == "declaration":
        match = _extract_local_var_from_declaration(node, *args, **kwargs)
        if match:
            return match

    # Avoid descending into struct/union field lists to prevent treating fields as locals.
    if node.type in {"struct_specifier", "union_specifier", "enum_specifier"}:
        return None

    for child in node.children:
        match = _walk_for_local_declaration(child, *args, **kwargs)
        if match:
            return match
    return None


def get_local_var_type(function_name: str, var_name: str) -> Dict[str, Any]:
    """
    Retrieve the type and definition information for a local variable.

    Args:
        function_name: Name of the function containing the variable.
        var_name: Local variable identifier to locate.

    Returns:
        {
            "var_name": str,
            "type": str,
            "location": "file.c:123",
            "code_line": "...",
        }
        or {"error": "..."} when lookup fails.
    """
    if not isinstance(function_name, str) or not function_name.strip():
        return {"error": "function_name must be a non-empty string"}
    if not isinstance(var_name, str) or not var_name.strip():
        return {"error": "var_name must be a non-empty string"}

    func_meta = find_function_body(function_name)
    if not func_meta or func_meta.get("error"):
        return {"error": f"Unable to locate function body for {function_name}"}

    function_source = func_meta.get("function_body")
    if not isinstance(function_source, str) or not function_source.strip():
        return {"error": f"Function source for {function_name} is empty"}

    tree, code_bytes = _parse_function_ast(function_source)
    if tree is None or code_bytes is None:
        return {"error": "tree-sitter is not available or failed to parse the function source"}

    translation_unit = tree.root_node
    function_node = None

    def _find_function_definition(node):
        if node.type == "function_definition":
            return node
        for child in node.children:
            result = _find_function_definition(child)
            if result:
                return result
        return None

    function_node = _find_function_definition(translation_unit)
    if function_node is None:
        logging.debug(f"tree-sitter could not find explicit function definition for {function_name}; scanning entire snippet instead.")
        body_node = translation_unit
    else:
        body_node = function_node.child_by_field_name("body") or translation_unit

    function_start_line = func_meta.get("start_line") or 0
    try:
        function_start_line = int(function_start_line)
    except Exception:
        function_start_line = 0

    match = _walk_for_local_declaration(
        body_node,
        var_name,
        code_bytes,
        func_meta.get("filename"),
        function_start_line,
    )
    if match:
        return match
    return {"error": f"Local variable {var_name} not found in function {function_name}"}


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
    query = {
        "command" : "analysis-lvar",
        "location" : source_location,
        "eq_position" : str(eq_position)
    }
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
def get_detailed_value_sensitive_lvar_icfg_return_path(start_location: str, eq_position: int) -> Optional[List[Dict[str, Any]]]:
    # find-lvalue-detail-path-inside
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    command_caller = CommandCaller()
    query = {
        "command" : "find-lvalue-detail-path-inside",
        "location" : start_location,
        "eq_position" : str(eq_position) if eq_position is not None else "-1"
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding detailed value sensitive icfg return path for {start_location} with eq_position {eq_position}: {error}")
            return None
        else:
            return res_json
    return None

def get_value_sensitive_lvar_icfg_return_path(start_location: str, eq_position: int) -> Optional[List[Dict[str, Any]]]:
    if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', start_location):
        logging.error(f"Invalid source location format: {start_location}")
        return None
    command_caller = CommandCaller()
    query = {
        "command" : "find-lvalue-path-inside",
        "location" : start_location,
        "eq_position" : str(eq_position) if eq_position is not None else "-1"
    }
    res = command_caller.send_query(query)
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding value sensitive icfg return path for {start_location} with eq_position {eq_position}: {error}")
            return None
        else:
            del res_json["error"]
            return_locations = res_json.get("return_locations", [])
            return return_locations
    return None

def get_value_sensitive_arg_icfg_return_path(function_name: str, index: int) -> Optional[List[Dict[str, Any]]]:
    command_caller = CommandCaller()
    query = {
        "command" : "find-arg-value-path-inside",
        "function_name" : function_name,
        "arg_index" : str(index)
    }
    res = command_caller.send_query(query)
    print(f"res: {res}")
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            logging.error(f"Error finding value sensitive arg icfg return path for {function_name} with index {index}: {error}")
            return None
        else:
            del res_json["error"]
            return_locations = res_json.get("return_locations", [])
            return return_locations
    return None

def get_value_sensitive_call_arg_icfg_return_path(location: str, arg_index: int, callee_function_name: str = "") -> Optional[List[Dict[str, Any]]]:
    command_caller = CommandCaller()
    # {"command": "find-call-arg-value-path-inside", "location": "tif_dirread.c:5500", "arg_index": "2", "callee_function_name" : "TIFFReadDirEntrySlongArray"}
    query = {
        "command" : "find-call-arg-value-path-inside",
        "location" : location,
        "arg_index" : str(arg_index),
        "callee_function_name" : callee_function_name
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
        else:
            del res_json["error"]
            return_locations = res_json.get("return_locations", [])
            return return_locations
    return None

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
    query = {
        "command": "path-cond-func", # Assuming this is the command name in C++
        "start_location": start_location,
        "target_location": target_location
    }
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
    query = {
        "command": "path-cond-func",
        "start_location": start_location,
        "target_location": target_location
    }
    res = command_caller.send_query(query)
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
    query = {
        "command": "path-cond-func",
        "start_location": start_location,
        "target_location": target_location
    }
    res = command_caller.send_query(query)
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

def get_eq_position_list(source_location: str) -> Optional[List[int]]:
    # find-store-cl
    command_caller = CommandCaller()
    query = {
        "command" : "find-store-cl",
        "location" : source_location
    }
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

'''
control flow graph (CFG)
'''
def _extract_condition_expression(node, code_bytes: bytes) -> Optional[str]:
    """Extracts the condition expression from a conditional node.
    
    Args:
        node: tree-sitter node representing a conditional statement
        code_bytes: The source code as bytes
        
    Returns:
        The condition expression as a string, or None if not found
    """
    if node is None:
        return None
    
    # Try to find condition field
    condition_node = node.child_by_field_name("condition")
    if condition_node:
        return code_bytes[condition_node.start_byte:condition_node.end_byte].decode("utf8").strip()
    
    # For if/while/for statements, try common patterns
    if node.type in ["if_statement", "while_statement", "for_statement", "do_statement"]:
        for child in node.children:
            if child.type == "parenthesized_expression":
                return code_bytes[child.start_byte:child.end_byte].decode("utf8").strip()
            elif child.type == "condition":
                return code_bytes[child.start_byte:child.end_byte].decode("utf8").strip()
    
    return None


def get_cfg_by_function_name(function_name: str) -> Optional[Dict[str, Any]]:
    """Builds a control flow graph (CFG) for a function using tree-sitter.
    
    This function constructs the CFG entirely using tree-sitter AST parsing,
    without relying on the backend graph-reader.
    
    Args:
        function_name: The name of the function to build CFG for
        
    Returns:
        A dictionary containing:
        {
            "function_name": str,
            "filename": str,
            "nodes": [
                {
                    "node_id": int,
                    "type": str,  # "normal", "entry", "exit", "branch", "loop_entry", etc.
                    "start_line": int,
                    "end_line": int,
                    "statements": List[str],  # Code lines
                    "location": str  # "filename:start_line"
                },
                ...
            ],
            "edges": [
                {
                    "source": int,  # Source node ID
                    "target": int,  # Target node ID
                    "type": str,  # "sequential", "true_branch", "false_branch", "loop_body", etc.
                    "condition": Optional[str]  # Condition expression if applicable
                },
                ...
            ]
        }
        Returns None if the function cannot be found or parsed.
    """
    if not isinstance(function_name, str) or not function_name.strip():
        logging.error("function_name must be a non-empty string")
        return None
    
    # Get function body
    func_meta = find_function_body(function_name)
    if not func_meta or func_meta.get("error"):
        logging.error(f"Unable to locate function body for {function_name}")
        return None
    
    function_source = func_meta.get("function_body")
    if not isinstance(function_source, str) or not function_source.strip():
        logging.error(f"Function source for {function_name} is empty")
        return None
    
    filename = func_meta.get("filename", "")
    function_start_line = func_meta.get("start_line") or 0
    function_end_line = func_meta.get("end_line") or 0
    try:
        function_start_line = int(function_start_line)
    except Exception:
        function_start_line = 0
    try:
        function_end_line = int(function_end_line)
    except Exception:
        function_end_line = 0
    
    # Parse AST
    tree, code_bytes = _parse_function_ast(function_source)
    if tree is None or code_bytes is None:
        logging.error("tree-sitter is not available or failed to parse the function source")
        return None
    
    translation_unit = tree.root_node
    
    # Find function definition node
    def _find_function_definition(node):
        if node.type == "function_definition":
            return node
        for child in node.children:
            result = _find_function_definition(child)
            if result:
                return result
        return None
    
    function_node = _find_function_definition(translation_unit)
    if function_node is None:
        logging.debug(f"tree-sitter could not find explicit function definition for {function_name}; scanning entire snippet instead.")
        body_node = translation_unit
        body_start_line = function_start_line
    else:
        body_node = function_node.child_by_field_name("body") or translation_unit
        # Calculate actual body start line
        # body_node.start_point[0] is relative to the parsed function source (function_source)
        # Since function_source starts at function_start_line, we need to add the offset
        if body_node and body_node != translation_unit:
            # Find the opening brace line in the function source
            # The body node's start_point[0] gives us the relative line offset
            body_offset = body_node.start_point[0]  # 0-based line offset in function_source
            body_start_line = function_start_line + body_offset
        else:
            body_start_line = function_start_line
    
    # Build basic blocks and edges
    # Pass both function_start_line (for absolute line calculation) and body_start_line (for entry node)
    result = _build_cfg_from_body(body_node, code_bytes, function_start_line, body_start_line, filename, function_name, function_end_line)
    return result


def _build_cfg_from_body(body_node, code_bytes: bytes, function_start_line: int, body_start_line: int, filename: str, function_name: str, function_end_line: int = 0) -> Dict[str, Any]:
    """Builds CFG from function body node.
    
    Args:
        body_node: tree-sitter node representing function body
        code_bytes: Source code as bytes
        function_start_line: Starting line number of the function (for calculating absolute line numbers)
        body_start_line: Starting line number of the function body (first '{' line, for entry node)
        filename: Source filename
        function_name: Function name
        function_end_line: Ending line number of the function (for exit node)
        
    Returns:
        CFG dictionary with nodes and edges
    """
    nodes = []
    edges = []
    next_node_id = 0
    
    # Create entry node
    entry_node_id = next_node_id
    next_node_id += 1
    entry_node = {
        "node_id": entry_node_id,
        "type": "entry",
        "start_line": body_start_line,
        "end_line": body_start_line,
        "statements": [],
        "location": f"{filename}:{body_start_line}"
    }
    nodes.append(entry_node)
    
    # Build basic blocks from body
    basic_blocks = _build_basic_blocks(
        body_node,
        code_bytes,
        function_start_line,
        function_end_line,
        filename,
        next_node_id,
    )
    next_node_id = basic_blocks.get("next_id", next_node_id)
    
    # Add all basic blocks to nodes
    nodes.extend(basic_blocks.get("blocks", []))
    
    # Build control flow edges (before adding exit node to avoid conflicts)
    cfg_edges = _build_cfg_edges(body_node, basic_blocks, code_bytes, entry_node_id)
    edges.extend(cfg_edges)
    
    # Find exit nodes (nodes ending with return or reaching end)
    exit_nodes = _find_exit_nodes(basic_blocks.get("blocks", []), body_node)
    
    # Determine exit node line number
    # Use the maximum line number from exit nodes, or function_end_line, or last block
    exit_line = body_start_line  # Default fallback
    if exit_nodes:
        # Use the maximum line number from all exit nodes
        exit_line = max(exit_n.get("end_line", exit_n.get("start_line", body_start_line)) for exit_n in exit_nodes)
    elif function_end_line > 0:
        # Use function end line if available
        exit_line = function_end_line
    elif basic_blocks.get("blocks"):
        # Use last block's end line
        last_block = basic_blocks["blocks"][-1]
        exit_line = last_block.get("end_line", last_block.get("start_line", body_start_line))
    
    # Create exit node and connect
    exit_node_id = next_node_id
    next_node_id += 1
    exit_node = {
        "node_id": exit_node_id,
        "type": "exit",
        "start_line": exit_line,
        "end_line": exit_line,
        "statements": [],
        "location": f"{filename}:{exit_line}"
    }
    nodes.append(exit_node)
    
    if exit_nodes:
        # Connect all return nodes to the exit node
        for exit_n in exit_nodes:
            edges.append({
                "source": exit_n["node_id"],
                "target": exit_node_id,
                "type": "sequential",
                "condition": None
            })
            print(f"DEBUG: Connected return node {exit_n['node_id']} to exit node {exit_node_id}")
            
    # Connect last block to exit node if it's not a return/jump (fallthrough)
    if basic_blocks.get("blocks"):
        last_block = basic_blocks["blocks"][-1]
        last_block_type = last_block.get("type")
        last_stmts = last_block.get("statements", [])
        
        is_jump = False
        if last_block_type in ["return", "goto", "break", "continue"]:
            is_jump = True
        elif last_stmts:
            last_stmt = last_stmts[-1]
            if any(k in last_stmt for k in ["return", "goto", "break", "continue"]):
                is_jump = True
        
        # Check if we already connected it (it would be covered by !is_jump check above if logic holds, 
        # but let's be explicit if it wasn't connected)
        edge_exists = any(e["source"] == last_block["node_id"] for e in edges)
        
        # NOTE: Be careful not to connect arbitrary blocks to exit if they are inside a structure
        # Only the truly LAST block of the function execution flow should fall through to exit.
        # But 'last_block' here is just the last in the list.
        # If 'last_block' is inside a switch case (e.g. default case), it should NOT go to exit unless it's the last statement of function.
        
        if not is_jump and not edge_exists:
            # Only connect if this block is actually at the end of the function
            # Simple heuristic: check if end_line is close to exit_line
            # Or if it's the last block created
            
            # For now, let's keep it but maybe it's the source of "case -> exit" issue if 'default' is last in list?
            # If 'default' is last block in list, but followed by 'switch_end' logic which jumps elsewhere?
            # No, 'blocks' list order reflects creation order.
            
            edges.append({
                "source": last_block["node_id"],
                "target": exit_node_id,
                "type": "sequential",
                "condition": None
            })
            print(f"DEBUG: Connected last block {last_block['node_id']} (fallthrough) to exit node {exit_node_id}")
            
    # Also connect any label blocks that are at the very end (e.g. fail_return:)
    # If the last block is a label, it might be the target of a jump and then fall through to exit
    if basic_blocks.get("blocks"):
        last_block = basic_blocks["blocks"][-1]
        if last_block.get("type") == "label":
             # Check if we already connected it (it would be covered by !is_jump check above if logic holds, 
             # but let's be explicit if it wasn't connected)
             edge_exists = any(e["source"] == last_block["node_id"] and e["target"] == exit_node_id for e in edges)
             if not edge_exists:
                edges.append({
                    "source": last_block["node_id"],
                    "target": exit_node_id,
                    "type": "sequential",
                    "condition": None
                })
                print(f"DEBUG: Connected end label block {last_block['node_id']} to exit node {exit_node_id}")

    # Connect entry node to first basic block
    if basic_blocks.get("blocks"):
        first_block = basic_blocks["blocks"][0]
        edges.insert(0, {
            "source": entry_node_id,
            "target": first_block["node_id"],
            "type": "sequential",
            "condition": None
        })
    
    return {
        "function_name": function_name,
        "filename": filename,
        "nodes": nodes,
        "edges": edges
    }


def _build_basic_blocks(
    body_node,
    code_bytes: bytes,
    function_start_line: int,
    function_end_line: int,
    filename: str,
    start_node_id: int,
) -> Dict[str, Any]:
    """Builds basic blocks from function body.
    
    This function traverses the AST and creates basic blocks while tracking
    control flow structures for later edge building.
    
    Args:
        body_node: tree-sitter node representing function body
        code_bytes: Source code as bytes
        function_start_line: Starting line number of the function (for calculating absolute line numbers)
        filename: Source filename
        start_node_id: Starting node ID for blocks
        
    Returns:
        Dictionary with:
        - "blocks": List of basic block dictionaries
        - "next_id": Next available node ID
        - "structure_map": Map of control flow structures for edge building
    """
    blocks = []
    structure_map = []  # Track control flow structures: (type, condition_node_id, then_start, else_start, etc.)
    goto_map = []  # Track goto statements: (block_id, target_label_name)
    label_map = {}  # Map label names to node IDs: {label_name: node_id}
    current_node_id = start_node_id
    current_block_statements = []
    current_block_start_line = None
    current_block_end_line = None
    current_block_type = "normal"
    
    def add_current_block():
        nonlocal current_block_statements, current_block_start_line, current_block_end_line, current_block_type, current_node_id
        
        if current_block_start_line is not None:
            block = {
                "node_id": current_node_id,
                "type": current_block_type,
                "start_line": current_block_start_line,
                "end_line": current_block_end_line or current_block_start_line,
                "statements": list(current_block_statements),
                "location": f"{filename}:{current_block_start_line}"
            }
            blocks.append(block)
            block_id = current_node_id
            current_node_id += 1
            
            # Reset for next block
            current_block_statements = []
            current_block_start_line = None
            current_block_end_line = None
            current_block_type = "normal"
            
            return block_id
        
        return None
    
    def _link_switch_case(line_no: int, label_type: str, node_id: int):
        """Attach generated block id to corresponding switch case label record."""
        for structure in reversed(structure_map):
            if structure.get("type") != "switch":
                continue
            for label in structure.get("case_labels", []):
                if label.get("node_id") is not None:
                    continue
                if label_type == "default":
                    if label.get("value") == "default" and label.get("line") == line_no:
                        label["node_id"] = node_id
                        print(f"DEBUG: Linked default case at line {line_no} to node {node_id}")
                        return
                else:
                    if label.get("value") != "default" and label.get("line") == line_no:
                        label["node_id"] = node_id
                        print(
                            f"DEBUG: Linked case value {label.get('value')} at line {line_no} to node {node_id}"
                        )
                        return

    def process_statement(node, line_offset: int = 0):
        """Process a statement node and add to current block or create new blocks."""
        nonlocal current_block_statements, current_block_start_line, current_block_end_line, current_block_type, current_node_id, blocks, structure_map
        
        if node is None:
            return None
        
        # node.start_point[0] is relative to the parsed function_source, which starts at function_start_line
        # However, if we're processing body_node directly, start_point might be relative to body
        # Calculate line number based on the actual node position in source
        line_no = function_start_line + node.start_point[0] + line_offset
        
        # Handle different statement types
        if node.type == "if_statement":
            # Finish current block
            prev_block_id = add_current_block()
            
            # Create branch node for the condition
            # The line_no should be the line where 'if' keyword appears
            condition = _extract_condition_expression(node, code_bytes)
            branch_block_id = current_node_id
            branch_block = {
                "node_id": branch_block_id,
                "type": "branch",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()],
                "location": f"{filename}:{line_no}",
                "condition": condition,
                "control_structure": "if"
            }
            blocks.append(branch_block)
            current_node_id += 1
            print(f"DEBUG: Created if branch node {branch_block_id} at {filename}:{line_no} (if statement starts at line {line_no})")
            
            # Process then branch
            then_node = node.child_by_field_name("consequence")
            then_start_id = None
            then_end_id = None
            then_ends_with_jump = False  # Track if then branch ends with goto/return
            if then_node:
                blocks_before_then = len(blocks)
                stmts_before_then = len(current_block_statements)
                
                then_start_id = process_statement(then_node)
                
                blocks_after_then = len(blocks)
                stmts_after_then = len(current_block_statements)
                
                # If statements were added but no block created, flush them now to create the then block
                if then_start_id is None and stmts_after_then > stmts_before_then:
                    then_start_id = add_current_block()
                    blocks_after_then = len(blocks) # Update count
                
                # If no new block was created and no statements added (e.g., empty compound or weird single line),
                # create a block for the then branch
                if then_start_id is None and blocks_after_then == blocks_before_then:
                    # Single-line if statement - create a block for the then branch
                    then_line_no = function_start_line + then_node.start_point[0]
                    then_stmt_text = code_bytes[then_node.start_byte:then_node.end_byte].decode("utf8").strip()
                    then_block_id = current_node_id
                    then_block = {
                        "node_id": then_block_id,
                        "type": "normal",
                        "start_line": then_line_no,
                        "end_line": then_line_no,
                        "statements": [then_stmt_text],
                        "location": f"{filename}:{then_line_no}"
                    }
                    blocks.append(then_block)
                    current_node_id += 1
                    then_start_id = then_block_id
                    then_end_id = then_block_id
                    print(f"DEBUG: Created block for single-line if then branch: {then_block_id} at {filename}:{then_line_no}")
                
                # Check if then branch ends with goto/return
                if blocks_after_then > blocks_before_then:
                    last_then_block = blocks[-1]
                    statements = last_then_block.get("statements", [])
                    if statements:
                        last_stmt = statements[-1]
                        if any(keyword in last_stmt for keyword in ["goto", "return"]):
                            then_ends_with_jump = True
                    elif last_then_block.get("type") in ["return", "goto"]:
                        then_ends_with_jump = True
                
                # Find the last block created in the then branch
                if blocks_after_then > blocks_before_then:
                    # The last block in then branch
                    then_end_id = blocks[-1]["node_id"]
                elif then_start_id:
                    # If no new blocks were created (but then_start_id set via flush), then_start_id is the only block
                    then_end_id = then_start_id
            
            # Process else branch if exists
            else_node = node.child_by_field_name("alternative")
            else_start_id = None
            else_end_id = None
            if else_node:
                # Find the line number where else keyword should be
                # The else keyword is typically on the line before else_node if else_node is a compound_statement
                else_node_line = function_start_line + else_node.start_point[0]
                
                # If else_node is a compound_statement starting with '{', 
                # the else keyword is likely on the previous line
                if else_node.type == "compound_statement":
                    # Check if the first character of else_node is '{'
                    else_node_text = code_bytes[else_node.start_byte:else_node.start_byte+1].decode("utf8", errors="ignore").strip()
                    if else_node_text == "{":
                        # else { ... } - else keyword is on the line before the opening brace
                        else_keyword_line = else_node_line - 1 if else_node_line > function_start_line else else_node_line
                    else:
                        # else keyword might be on the same line
                        else_keyword_line = else_node_line
                else:
                    # else statement; - else keyword is on the same line as the statement
                    else_keyword_line = else_node_line
                
                # Create a block for the else keyword to ensure false_branch points to the correct location
                else_keyword_block_id = current_node_id
                else_keyword_block = {
                    "node_id": else_keyword_block_id,
                    "type": "normal",
                    "start_line": else_keyword_line,
                    "end_line": else_keyword_line,
                    "statements": ["else"],  # Mark this as the else keyword block
                    "location": f"{filename}:{else_keyword_line}"
                }
                blocks.append(else_keyword_block)
                current_node_id += 1
                else_start_id = else_keyword_block_id  # Use the else keyword block as the start
                print(f"DEBUG: Created else keyword block {else_keyword_block_id} at {filename}:{else_keyword_line} (else_node at line {else_node_line})")
                
                blocks_before_else = len(blocks)
                stmts_before_else = len(current_block_statements)
                
                # Process the else branch content
                else_content_start_id = process_statement(else_node)
                
                blocks_after_else = len(blocks)
                stmts_after_else = len(current_block_statements)
                
                # If statements were added but no block created, flush them now
                if else_content_start_id is None and stmts_after_else > stmts_before_else:
                    # The flushed block becomes part of the else branch
                    flushed_id = add_current_block()
                    blocks_after_else = len(blocks)
                    if flushed_id is not None:
                        # If process_statement returned None, this flush ID is the start of content
                        else_content_start_id = flushed_id

                # If else branch created new blocks, ensure else_start_id points to the first one
                if blocks_after_else > blocks_before_else:
                    # New blocks were created - else_start_id should point to the first new block
                    # But wait, we already created else_keyword_block and set else_start_id to it.
                    # That is correct: false_branch -> else_keyword -> else_content
                    # We just need to track else_end_id
                    else_end_id = blocks[-1]["node_id"]
                    print(f"DEBUG: Else branch created {blocks_after_else - blocks_before_else} block(s), else_start_id={else_start_id}, else_end_id={else_end_id}")
                elif else_content_start_id is None and blocks_after_else == blocks_before_else:
                    # Empty else branch - check if it's an empty compound statement
                    if else_node.type == "compound_statement":
                        # Empty else block - we'll use if_end_id for false_branch
                        # But we still need to mark that else exists
                        # We have else_keyword_block, so else_start_id is valid.
                        else_end_id = else_start_id
                    else:
                        # Single-line else without braces - create a block
                        else_line_no = function_start_line + else_node.start_point[0]
                        else_stmt_text = code_bytes[else_node.start_byte:else_node.end_byte].decode("utf8").strip()
                        else_block_id = current_node_id
                        else_block = {
                            "node_id": else_block_id,
                            "type": "normal",
                            "start_line": else_line_no,
                            "end_line": else_line_no,
                            "statements": [else_stmt_text],
                            "location": f"{filename}:{else_line_no}"
                        }
                        blocks.append(else_block)
                        current_node_id += 1
                        # Connect else_keyword to this block
                        # (Implicitly handled by sequential edges later? No, we need to ensure flow)
                        # Actually, sequential edges will handle else_keyword -> else_block
                        else_end_id = else_block_id
                        print(f"DEBUG: Created block for single-line else branch: {else_block_id} at {filename}:{else_line_no}")
                elif else_content_start_id:
                     # Content started, but no new blocks (unlikely if flush logic works)
                     else_end_id = else_content_start_id
                else:
                     # Fallback
                     else_end_id = else_start_id
            
            # Find the block that comes after the entire if statement
            # This is needed for false branch when then ends with goto/return
            blocks_before_if_end = len(blocks)
            # After processing if-else, ensure any subsequent statements start a new block
            add_current_block()
            blocks_after_if_end = len(blocks)
            if_end_id = None
            if blocks_after_if_end > blocks_before_if_end:
                # A new block was created after the if statement
                if_end_id = blocks[-1]["node_id"]
            # Note: If no new block yet, we'll find it later in _build_cfg_edges using _find_block_after
            
            # Track structure for edge building
            structure_map.append({
                "type": "if",
                "condition_id": branch_block_id,
                "prev_id": prev_block_id,
                "then_start_id": then_start_id,
                "then_end_id": then_end_id,
                "then_ends_with_jump": then_ends_with_jump,  # Track if then ends with goto/return
                "else_start_id": else_start_id,
                "else_end_id": else_end_id,
                "has_else": else_node is not None,  # Track if else branch exists (even if empty)
                "if_end_id": if_end_id  # Block after entire if statement
            })
            
            return branch_block_id
        
        elif node.type == "while_statement":
            # Finish current block
            prev_block_id = add_current_block()
            
            # Create loop entry node
            condition = _extract_condition_expression(node, code_bytes)
            loop_entry_id = current_node_id
            loop_entry_block = {
                "node_id": loop_entry_id,
                "type": "loop_entry",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()],
                "location": f"{filename}:{line_no}",
                "condition": condition,
                "control_structure": "while"
            }
            blocks.append(loop_entry_block)
            current_node_id += 1
            
            # Process loop body
            body_node_inner = node.child_by_field_name("body")
            body_start_id = None
            if body_node_inner:
                body_start_id = process_statement(body_node_inner)
            
            # After processing loop, ensure any subsequent statements start a new block
            # This creates the block after the loop, which we need for the false branch
            loop_exit_id = add_current_block()
            # If no block was created, we'll find it later in edge building
            # For now, store the current_node_id as a marker for the next block
            if loop_exit_id is None:
                loop_exit_id = current_node_id  # Next block to be created
            
            structure_map.append({
                "type": "while",
                "condition_id": loop_entry_id,
                "prev_id": prev_block_id,
                "body_start_id": body_start_id,
                "loop_exit_id": loop_exit_id  # Block after loop (for false branch)
            })
            
            return loop_entry_id
        
        elif node.type == "for_statement":
            # Finish current block
            prev_block_id = add_current_block()
            
            # Create loop entry node
            condition = _extract_condition_expression(node, code_bytes)
            loop_entry_id = current_node_id
            loop_entry_block = {
                "node_id": loop_entry_id,
                "type": "loop_entry",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()],
                "location": f"{filename}:{line_no}",
                "condition": condition,
                "control_structure": "for"
            }
            blocks.append(loop_entry_block)
            current_node_id += 1
            
            # Process loop body
            body_node_inner = node.child_by_field_name("body")
            body_start_id = None
            if body_node_inner:
                body_start_id = process_statement(body_node_inner)
            
            # After processing loop, ensure any subsequent statements start a new block
            # This creates the block after the loop, which we need for the false branch
            loop_exit_id = add_current_block()
            # If no block was created, we'll find it later in edge building
            # For now, store the current_node_id as a marker for the next block
            if loop_exit_id is None:
                loop_exit_id = current_node_id  # Next block to be created
            
            structure_map.append({
                "type": "for",
                "condition_id": loop_entry_id,
                "prev_id": prev_block_id,
                "body_start_id": body_start_id,
                "loop_exit_id": loop_exit_id  # Block after loop (for false branch)
            })
            
            return loop_entry_id
        
        elif node.type == "do_statement":
            # Finish current block
            prev_block_id = add_current_block()
            
            # Process loop body first
            body_node_inner = node.child_by_field_name("body")
            body_start_id = None
            if body_node_inner:
                body_start_id = process_statement(body_node_inner)
            
            # Create loop condition node
            condition = _extract_condition_expression(node, code_bytes)
            loop_entry_id = current_node_id
            loop_entry_block = {
                "node_id": loop_entry_id,
                "type": "loop_entry",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()],
                "location": f"{filename}:{line_no}",
                "condition": condition,
                "control_structure": "do"
            }
            blocks.append(loop_entry_block)
            current_node_id += 1
            
            structure_map.append({
                "type": "do",
                "condition_id": loop_entry_id,
                "prev_id": prev_block_id,
                "body_start_id": body_start_id
            })
            
            # After processing loop, ensure any subsequent statements start a new block
            add_current_block()
            
            return loop_entry_id
        
        elif node.type == "switch_statement":
            # Finish current block
            prev_block_id = add_current_block()
            
            # Create switch node
            condition = _extract_condition_expression(node, code_bytes)
            switch_block_id = current_node_id
            switch_block = {
                "node_id": switch_block_id,
                "type": "switch",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()],
                "location": f"{filename}:{line_no}",
                "condition": condition
            }
            blocks.append(switch_block)
            current_node_id += 1
            
            # Track case labels for switch
            case_labels = []
            body_node_inner = node.child_by_field_name("body")
            if body_node_inner:
                # Collect case labels before processing body (actual block creation happens later)
                for child in body_node_inner.children:
                    if child.type == "case_statement":
                        case_line = function_start_line + child.start_point[0]
                        case_expr_node = child.child_by_field_name("value")
                        case_value = None
                        if case_expr_node:
                            case_value = code_bytes[case_expr_node.start_byte:case_expr_node.end_byte].decode("utf8").strip()
                        case_labels.append({
                            "line": case_line,
                            "value": case_value,
                            "node_id": None  # Will be set when we process the block
                        })
                    elif child.type == "default_statement":
                        case_labels.append({
                            "line": function_start_line + child.start_point[0],
                            "value": "default",
                            "node_id": None
                        })
            
            print(
                f"DEBUG: Collected switch cases at {filename}:{line_no}: "
                f"{[(label.get('value'), label.get('line')) for label in case_labels]}"
            )
            switch_structure_entry = {
                "type": "switch",
                "condition_id": switch_block_id,
                "prev_id": prev_block_id,
                "case_labels": case_labels,
                "switch_end_id": None # Will be populated later
            }
            structure_map.append(switch_structure_entry)
            
            # Process switch body after registering structure so case/default nodes can link back
            if body_node_inner:
                process_statement(body_node_inner)
            
            # After processing switch, ensure any subsequent statements start a new block
            switch_end_id = add_current_block()
            # 如果 switch 后没有产生实际 block，显式补一个占位 block，保证 break 可以连向有效节点
            if switch_end_id is None:
                switch_end_line = function_start_line + (
                    body_node_inner.end_point[0] if body_node_inner else node.end_point[0]
                )
                switch_end_id = current_node_id
                blocks.append(
                    {
                        "node_id": switch_end_id,
                        "type": "switch_end",
                        "start_line": switch_end_line,
                        "end_line": switch_end_line,
                        "statements": [],
                        "location": f"{filename}:{switch_end_line}",
                    }
                )
                current_node_id += 1
            
            # Update the structure entry with the end ID
            switch_structure_entry["switch_end_id"] = switch_end_id
            
            return switch_block_id
        
        elif node.type == "case_statement":
            # Case statement - treat as a label
            prev_block_id = add_current_block()
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            case_block_id = current_node_id
            case_block = {
                "node_id": case_block_id,
                "type": "case",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [stmt_text],
                "location": f"{filename}:{line_no}"
            }
            blocks.append(case_block)
            current_node_id += 1
            _link_switch_case(line_no, "case", case_block_id)
            print(f"DEBUG: Created case block {case_block_id} for line {line_no}")
            
            # Process the statements after the case label
            # In tree-sitter, case_statement children are: "case", value, ":", and then statements
            value_node = node.child_by_field_name("value")
            
            for child in node.children:
                # Skip the case keyword and colon
                if child.type in ["case", ":", "default"]:
                    continue
                # Skip the value node
                if value_node and child.id == value_node.id:
                    continue
                
                process_statement(child)
            
            return case_block_id
        
        elif node.type == "default_statement":
            # Default statement - treat as a label
            prev_block_id = add_current_block()
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            default_block_id = current_node_id
            default_block = {
                "node_id": default_block_id,
                "type": "default",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [stmt_text],
                "location": f"{filename}:{line_no}"
            }
            blocks.append(default_block)
            current_node_id += 1
            _link_switch_case(line_no, "default", default_block_id)
            print(f"DEBUG: Created default block {default_block_id} for line {line_no}")
            
            # Process the statements after the default label
            # In tree-sitter, default_statement children are: "default", ":", and then statements
            for child in node.children:
                # Skip the default keyword and colon
                if child.type in ["default", ":"]:
                    continue
                
                process_statement(child)
            
            return default_block_id
        
        elif node.type == "return_statement":
            # Finish current block first (if any)
            prev_block_id = add_current_block()
            # Create a new block for the return statement only
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            return_block_id = current_node_id
            return_block = {
                "node_id": return_block_id,
                "type": "return",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [stmt_text],
                "location": f"{filename}:{line_no}"
            }
            blocks.append(return_block)
            current_node_id += 1
            return return_block_id
        
        elif node.type == "goto_statement":
            # Finish current block first (if any statements pending)
            prev_block_id = add_current_block()
            
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            
            # Extract target label name from goto statement
            # goto_statement structure: "goto" identifier ";"
            target_label = None
            for child in node.children:
                if child.type == "identifier":
                    target_label = code_bytes[child.start_byte:child.end_byte].decode("utf8").strip()
                    break
            
            # Fallback: try to extract from statement text using regex
            if not target_label:
                import re
                # Pattern: goto label_name;
                match = re.match(r'goto\s+(\w+)\s*;', stmt_text)
                if match:
                    target_label = match.group(1)
            
            # Create a new block for the goto statement only
            # This ensures the block location matches the goto statement line exactly
            goto_block_id = current_node_id
            goto_block = {
                "node_id": goto_block_id,
                "type": "normal",
                "start_line": line_no,
                "end_line": line_no,
                "statements": [stmt_text],
                "location": f"{filename}:{line_no}"
            }
            blocks.append(goto_block)
            current_node_id += 1
            
            # Record goto information
            if target_label:
                goto_map.append({
                    "block_id": goto_block_id,
                    "target_label": target_label,
                    "location": f"{filename}:{line_no}"
                })
                print(f"DEBUG: Found goto statement at {filename}:{line_no}, target label: {target_label}, block_id: {goto_block_id}")
            
            return goto_block_id
        
        elif node.type in ["break_statement", "continue_statement"]:
            # Add jump statement to current block
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            if current_block_start_line is None:
                current_block_start_line = line_no
            current_block_statements.append(stmt_text)
            current_block_end_line = line_no
            
            # Identify what this break/continue applies to
            # This is tricky without full scope tracking, but generally applies to the nearest enclosing loop/switch
            # We record the type so we can handle edges later
            block_type = "break" if node.type == "break_statement" else "continue"
            
            # Finish current block
            # Pass the type to add_current_block to set it on the block
            current_block_type = block_type 
            return add_current_block()
        
        elif node.type == "compound_statement":
            # Process statements in compound statement
            first_id = None
            for child in node.children:
                if child.type in ["{", "}"]:
                    continue
                result_id = process_statement(child)
                if first_id is None and result_id is not None:
                    first_id = result_id
            return first_id
        
        elif node.type == "labeled_statement":
            # Labeled statement - create new block for the label
            prev_block_id = add_current_block()
            
            # Extract label name
            # labeled_statement structure: label_name ":" statement
            # The first child is typically the label identifier
            label_name = None
            label_line_no = line_no
            
            for child in node.children:
                if child.type == "statement_label":
                    # statement_label contains the identifier
                    for grandchild in child.children:
                        if grandchild.type == "identifier":
                            label_name = code_bytes[grandchild.start_byte:grandchild.end_byte].decode("utf8").strip()
                            label_line_no = function_start_line + grandchild.start_point[0]
                            break
                    if label_name:
                        break
                elif child.type == "identifier":
                    # Sometimes the identifier is directly a child (before the colon)
                    label_name = code_bytes[child.start_byte:child.end_byte].decode("utf8").strip()
                    label_line_no = function_start_line + child.start_point[0]
                    break
                elif child.type == ":":
                    # Skip the colon
                    continue
            
            # Fallback: try to extract from statement text using regex
            # stmt_text contains the FULL labeled statement text (label: stmt)
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            if not label_name:
                import re
                # Pattern: label_name:
                match = re.match(r'^(\w+)\s*:', stmt_text)
                if match:
                    label_name = match.group(1)
            
            # For the block location, we want the line number of the label itself, not the whole statement
            # However, `line_no` passed to process_statement is the start line of the `labeled_statement` node
            # which *is* the line where the label starts.
            # But the user reports an off-by-one error.
            # The label block should represent the jump target.
            
            label_block_id = current_node_id
            label_block = {
                "node_id": label_block_id,
                "type": "label",
                "start_line": label_line_no,
                "end_line": label_line_no,
                "statements": [stmt_text], # This contains label + statement, maybe misleading?
                # Ideally, a label block is empty or contains just the label, and flows into the statement block
                # But here we make it contain the full text for context.
                "location": f"{filename}:{label_line_no}",
                "label_name": label_name
            }
            blocks.append(label_block)
            
            # Store label name to node ID mapping
            if label_name:
                label_map[label_name] = label_block_id
                print(f"DEBUG: Found label '{label_name}' at {filename}:{label_line_no}, block_id: {label_block_id}")
            
            current_node_id += 1
            
            # Process the statement after the label
            # The body of the labeled statement should be processed into its OWN block (or added to current)
            # which will naturally follow the label block sequentially.
            body_node_inner = node.child_by_field_name("body")
            if body_node_inner:
                # body_line_no = function_start_line + body_node_inner.start_point[0]
                # print(f"DEBUG: Processing labeled_statement body at {filename}:{body_line_no}, type: {body_node_inner.type}")
                process_statement(body_node_inner)
            else:
                # print(f"DEBUG: Labeled statement at {filename}:{line_no} has no body field")
                # In tree-sitter C grammar, labeled_statement structure is: label ":" statement
                # If body field doesn't exist, the statement might be a direct child
                # But we need to skip label-related nodes and find the actual statement
                found_statement = False
                for child in node.children:
                    # Skip label-related nodes
                    if child.type in ["statement_label", "identifier", ":", "statement_identifier"]:
                        continue
                    # Found a statement node (if_statement, expression_statement, etc.)
                    # child_line_no = function_start_line + child.start_point[0]
                    # print(f"DEBUG: Found child statement after label: type={child.type}, line={child_line_no}")
                    process_statement(child)
                    found_statement = True
                    break
                
                # if not found_statement:
                    # print(f"DEBUG: Warning: No statement found after label at {filename}:{line_no}")
            
            return label_block_id
        
        elif node.type in ["expression_statement", "declaration"]:
            # Regular statement - add to current block
            stmt_text = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
            if current_block_start_line is None:
                current_block_start_line = line_no
            current_block_statements.append(stmt_text)
            current_block_end_line = line_no
            return None  # Don't create new block yet
        
        else:
            # Unknown statement type - try to process children
            for child in node.children:
                process_statement(child)
            return None
    
    # Process body node
    if body_node.type == "compound_statement":
        print(f"DEBUG: Processing compound_statement with {len(body_node.children)} children")
        for i, child in enumerate(body_node.children):
            if child.type in ["{", "}"]:
                continue
            child_line_no = function_start_line + child.start_point[0]
            print(f"DEBUG: Processing child {i} in compound_statement: type={child.type}, line={child_line_no}")
            result = process_statement(child)
            if result:
                print(f"DEBUG: Processed statement in compound_statement, returned node_id: {result}")
    else:
        result = process_statement(body_node)
        if result:
            print(f"DEBUG: Processed body_node (not compound), returned node_id: {result}")
    
    # Add final block if any
    add_current_block()
    
    print(f"DEBUG: _build_basic_blocks summary:")
    print(f"  Total blocks: {len(blocks)}")
    print(f"  Goto statements: {len(goto_map)}")
    print(f"  Labels: {len(label_map)}")
    if goto_map:
        print(f"  Goto map: {goto_map}")
    if label_map:
        print(f"  Label map: {label_map}")

    current_node_id = _ensure_line_coverage_blocks(
        blocks,
        filename,
        function_start_line,
        function_end_line,
        current_node_id,
    )
    
    return {
        "blocks": blocks,
        "next_id": current_node_id,
        "structure_map": structure_map,
        "goto_map": goto_map,
        "label_map": label_map
    }


def _ensure_line_coverage_blocks(
    blocks: List[Dict[str, Any]],
    filename: str,
    function_start_line: int,
    function_end_line: int,
    next_node_id: int,
) -> int:
    """Ensure every line within the function has at least one block representation."""
    if not blocks:
        return next_node_id

    covered_lines: Set[int] = set()
    for block in blocks:
        start = block.get("start_line")
        end = block.get("end_line", start)
        if start is None:
            continue
        if end is None or end < start:
            end = start
        for line in range(start, end + 1):
            covered_lines.add(line)

    existing_max = max((block.get("end_line") or block.get("start_line") or 0) for block in blocks)
    coverage_start = max(function_start_line or 0, 1)
    coverage_end = function_end_line if function_end_line and function_end_line >= coverage_start else existing_max
    if coverage_end < coverage_start:
        coverage_end = coverage_start

    placeholder_blocks: List[Dict[str, Any]] = []
    for line in range(coverage_start, coverage_end + 1):
        if line in covered_lines:
            continue
        raw_line = dump_source_line(filename, line)
        if not isinstance(raw_line, str):
            raw_line = ""
        placeholder_blocks.append({
            "node_id": next_node_id,
            "type": "placeholder",
            "start_line": line,
            "end_line": line,
            "statements": [raw_line.strip("\n")],
            "location": f"{filename}:{line}",
        })
        next_node_id += 1

    if placeholder_blocks:
        blocks.extend(placeholder_blocks)
        blocks.sort(key=lambda b: (b.get("start_line", 0), b["node_id"]))

    return next_node_id


def _build_cfg_edges(body_node, basic_blocks: Dict[str, Any], code_bytes: bytes, entry_node_id: int) -> List[Dict[str, Any]]:
    """Builds control flow edges between basic blocks.
    
    Args:
        body_node: tree-sitter node representing function body
        basic_blocks: Dictionary with "blocks" list and "structure_map"
        code_bytes: Source code as bytes
        entry_node_id: Entry node ID
        
    Returns:
        List of edge dictionaries
    """
    edges = []
    blocks = basic_blocks.get("blocks", [])
    structure_map = basic_blocks.get("structure_map", [])
    goto_map = basic_blocks.get("goto_map", [])
    label_map = basic_blocks.get("label_map", {})
    
    if not blocks:
        return edges
    
    # Create a map from node_id to block for quick lookup
    block_map = {block["node_id"]: block for block in blocks}
    
    # Track which blocks have outgoing edges already defined by control structures
    handled_blocks = set()
    
    # Build edges for goto statements
    print(f"DEBUG: Building goto edges from {len(goto_map)} goto statements")
    for goto_info in goto_map:
        goto_block_id = goto_info.get("block_id")
        target_label = goto_info.get("target_label")
        goto_location = goto_info.get("location", "unknown")
        
        if goto_block_id is None or not target_label:
            print(f"DEBUG: Skipping invalid goto: block_id={goto_block_id}, target={target_label}")
            continue
        
        # Find target label node
        target_node_id = label_map.get(target_label)
        if target_node_id is None:
            print(f"DEBUG: Warning: goto at {goto_location} targets unknown label '{target_label}'")
            continue
        
        # Create edge from goto block to label block
        edges.append({
            "source": goto_block_id,
            "target": target_node_id,
            "type": "goto",
            "condition": None,
            "label": target_label
        })
        handled_blocks.add(goto_block_id)
        print(f"DEBUG: Added goto edge: block {goto_block_id} -> label '{target_label}' (node {target_node_id})")
    
    # Build edges for break/continue statements
    # We need to find the target for each break/continue
    # Simple heuristic: find nearest enclosing loop/switch in structure_map
    # This requires knowing the nesting, which structure_map doesn't explicitly have, 
    # but we can infer based on node IDs (nested structures are processed between start/end of parent)
    # Actually, structure_map is appended in order of processing start.
    
    for block in blocks:
        block_type = block.get("type")
        if block_type in ["break", "continue"]:
            block_id = block["node_id"]
            
            # Find enclosing structure
            # We iterate structure_map in reverse to find the nearest enclosing one
            target_structure = None
            for structure in reversed(structure_map):
                # Check if block_id is "inside" this structure
                # This is hard because we don't track full range.
                # But we know structure_map is built during traversal.
                # A block is inside if its ID is > condition_id and < structure end (if known)
                # Or simply, the first structure we find searching backwards *that is still open*
                # But here we are post-processing.
                
                # Let's use a simpler approach:
                # Iterate structure_map and check if block_id is logically inside.
                # For loops: inside if between condition_id and loop_exit_id (exclusive)
                # For switch: inside if between condition_id and switch_end_id
                
                s_type = structure.get("type")
                cond_id = structure.get("condition_id")
                
                if s_type in ["while", "for", "do"]:
                    end_id = structure.get("loop_exit_id")
                    # If end_id is a future ID (not in blocks yet), resolve it
                    if end_id:
                         # Resolving future ID logic similar to loop processing...
                         # For now assume if block_id > cond_id, it might be inside.
                         # A better check: is block_id < end_id?
                         pass
                    
                    if block_id > cond_id:
                        if end_id and block_id < end_id:
                            target_structure = structure
                            # Break/continue matches nearest loop
                            break
                        elif not end_id:
                             # Should not happen if logic is correct
                             pass
                             
                elif s_type == "switch":
                    end_id = structure.get("switch_end_id")
                    if block_id > cond_id:
                        if end_id and block_id < end_id:
                            # Break matches switch, Continue does NOT match switch (goes to enclosing loop)
                            if block_type == "break":
                                target_structure = structure
                                break
                            else:
                                # Continue in switch applies to enclosing loop, keep searching
                                continue
            
            if target_structure:
                s_type = target_structure.get("type")
                target_node_id = None
                edge_type = "jump"
                
                if block_type == "break":
                    if s_type == "switch":
                        target_node_id = target_structure.get("switch_end_id")
                    elif s_type in ["while", "for", "do"]:
                        target_node_id = target_structure.get("loop_exit_id")
                elif block_type == "continue":
                    if s_type in ["while", "for"]:
                        target_node_id = target_structure.get("condition_id")
                    elif s_type == "do":
                        target_node_id = target_structure.get("condition_id") # For do-while, continue goes to condition? check C spec.
                        # Actually do-while continue goes to condition check usually at end, 
                        # but in our CFG condition is a node. 
                        # Ideally continue goes to condition check.
                        pass

                # Resolve future IDs for target
                if target_node_id:
                     # Check if target node exists
                     target_block = block_map.get(target_node_id)
                     if not target_block:
                         # Find first block >= target_node_id
                         for bid in sorted(block_map.keys()):
                             if bid >= target_node_id:
                                 target_node_id = bid
                                 break
                
                if target_node_id is not None and target_node_id in block_map:
                    edges.append({
                        "source": block_id,
                        "target": target_node_id,
                        "type": block_type,
                        "condition": None
                    })
                    handled_blocks.add(block_id)
                    print(f"DEBUG: Added {block_type} edge: {block_id} -> {target_node_id} (structure {s_type})")

    # Build edges for break/continue statements
    for block in blocks:
        block_type = block.get("type")
        if block_type in ["break", "continue"]:
            block_id = block["node_id"]
            
            # Find enclosing structure by iterating reversed structure_map
            target_structure = None
            
            # Since structure_map is in processing order (Outer -> Inner), reverse iteration
            # finds the most recently opened structure, which corresponds to the nearest enclosing one.
            # We need to verify if the block is actually "inside" it.
            # We can use node IDs: structures have condition_id (start).
            # If block_id > structure.condition_id, it started after the structure started.
            # We also need to check if the structure has ended before this block.
            # loop_exit_id/switch_end_id represent the block AFTER the structure.
            # If they are set and block_id >= end_id, then this block is AFTER the structure, not inside.
            # BUT: end_id might be set after the break is processed?
            # Yes, structure map entries are appended when structure *starts* processing (mostly),
            # but end_ids are updated after processing body.
            # Wait, my implementation appends to structure_map AFTER processing the body/branches?
            # Let's check:
            # if_statement: structure_map.append AFTER processing branches.
            # while_statement: structure_map.append AFTER processing body.
            # switch_statement: structure_map.append AFTER processing body.
            
            # This means structure_map contains structures that have FINISHED processing.
            # And they are ordered by finish time (Inner finishes before Outer).
            # So iterating reversed structure_map gives: Inner -> Outer.
            # And since they are finished, we have end_ids.
            # If block_id is inside [condition_id, end_id], then it belongs to this structure.
            
            for structure in reversed(structure_map):
                s_type = structure.get("type")
                cond_id = structure.get("condition_id")
                end_id = None
                
                if s_type in ["while", "for", "do"]:
                    end_id = structure.get("loop_exit_id")
                elif s_type == "switch":
                    end_id = structure.get("switch_end_id")
                elif s_type == "if":
                    end_id = structure.get("if_end_id")
                
                # If end_id is None (e.g. infinite loop with no exit block created yet?), use current max?
                # But here we are post-processing, so end_ids should be populated if blocks exist.
                
                if end_id is not None:
                    if block_id > cond_id and block_id < end_id:
                        # Found enclosing structure
                        # Check if it's a valid target for break/continue
                        if block_type == "break" and s_type in ["switch", "while", "for", "do"]:
                            target_structure = structure
                            break
                        elif block_type == "continue" and s_type in ["while", "for", "do"]:
                            target_structure = structure
                            break
                else:
                    # If end_id is None (e.g. last structure in function), check if block > cond
                    if block_id > cond_id:
                         # Potentially inside
                         if block_type == "break" and s_type in ["switch", "while", "for", "do"]:
                            target_structure = structure
                            break
                         elif block_type == "continue" and s_type in ["while", "for", "do"]:
                            target_structure = structure
                            break
            
            if target_structure:
                s_type = target_structure.get("type")
                target_node_id = None
                
                if block_type == "break":
                    if s_type == "switch":
                        target_node_id = target_structure.get("switch_end_id")
                    elif s_type in ["while", "for", "do"]:
                        target_node_id = target_structure.get("loop_exit_id")
                elif block_type == "continue":
                    if s_type in ["while", "for", "do"]:
                        target_node_id = target_structure.get("condition_id")
                
                # Resolve future/marker IDs if necessary
                if target_node_id is not None:
                     # Check if target node exists in block_map
                     if target_node_id not in block_map:
                         # Find first block >= target_node_id
                         for bid in sorted(block_map.keys()):
                             if bid >= target_node_id:
                                 target_node_id = bid
                                 break
                
                if target_node_id is not None: # and target_node_id in block_map (allow edge to exit which is not in block_map? No, exit is not target here usually)
                    edges.append({
                        "source": block_id,
                        "target": target_node_id,
                        "type": block_type,
                        "condition": None
                    })
                    handled_blocks.add(block_id)
                    print(f"DEBUG: Added {block_type} edge: {block_id} -> {target_node_id} (structure {s_type})")

    # Build edges for control flow structures
    for structure in structure_map:
        struct_type = structure.get("type")
        condition_id = structure.get("condition_id")
        
        if struct_type == "if":
            # If statement: condition -> then branch (true) or else branch (false)
            condition_block = block_map.get(condition_id)
            if condition_block:
                condition_expr = condition_block.get("condition")
                
                then_start_id = structure.get("then_start_id")
                then_end_id = structure.get("then_end_id")  # Now tracked in structure_map
                then_ends_with_jump = structure.get("then_ends_with_jump", False)
                else_start_id = structure.get("else_start_id")
                else_end_id = structure.get("else_end_id")  # Now tracked in structure_map
                has_else = structure.get("has_else", False)  # Whether else branch exists
                if_end_id = structure.get("if_end_id")  # Block after entire if statement
                
                # If not tracked, try to find them
                if then_end_id is None and then_start_id:
                    then_end_id = _find_block_after(blocks, then_start_id)
                if else_end_id is None and else_start_id:
                    else_end_id = _find_block_after(blocks, else_start_id)
                
                # If if_end_id is None, try to find the block after the entire if statement
                # This is the block that comes after both then and else branches
                if if_end_id is None:
                    # Find the block after the else branch (if exists) or after the then branch
                    if else_end_id:
                        if_end_id = _find_block_after(blocks, else_end_id)
                    elif then_end_id:
                        if_end_id = _find_block_after(blocks, then_end_id)
                    # If still None, try to find the block after the condition node
                    if if_end_id is None:
                        if_end_id = _find_block_after(blocks, condition_id)
                
                print(f"DEBUG: Processing if statement at condition {condition_id}:")
                print(f"  then_start_id={then_start_id}, then_end_id={then_end_id}")
                print(f"  else_start_id={else_start_id}, else_end_id={else_end_id}")
                print(f"  if_end_id={if_end_id}")
                
                # True branch edge
                if then_start_id:
                    edges.append({
                        "source": condition_id,
                        "target": then_start_id,
                        "type": "true_branch",
                        "condition": condition_expr
                    })
                    handled_blocks.add(condition_id)
                    print(f"  Added true_branch: {condition_id} -> {then_start_id}")
                    
                    # If then branch doesn't end with goto/return, connect then_end to if_end
                    if not then_ends_with_jump and then_end_id and if_end_id:
                        # Check if then_end doesn't already have an outgoing edge
                        then_end_block = block_map.get(then_end_id)
                        if then_end_block:
                            then_end_statements = then_end_block.get("statements", [])
                            then_end_has_jump = False
                            if then_end_statements:
                                last_stmt = then_end_statements[-1]
                                if any(keyword in last_stmt for keyword in ["return", "break", "continue", "goto"]):
                                    then_end_has_jump = True
                            
                            if not then_end_has_jump and then_end_block.get("type") != "return":
                                edges.append({
                                    "source": then_end_id,
                                    "target": if_end_id,
                                    "type": "sequential",
                                    "condition": None
                                })
                                handled_blocks.add(then_end_id)
                                print(f"  Added then_end -> if_end edge: {then_end_id} -> {if_end_id}")
                
                # False branch edge (else or next block after if)
                if else_start_id:
                    # Has else branch with content - false goes to else
                    edges.append({
                        "source": condition_id,
                        "target": else_start_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (else): {condition_id} -> {else_start_id}")
                elif has_else and if_end_id:
                    # Else branch exists but is empty - false goes to if_end
                    edges.append({
                        "source": condition_id,
                        "target": if_end_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (empty else -> if_end): {condition_id} -> {if_end_id}")
                    
                    # Connect else_end to if_end if else doesn't end with goto/return
                    if else_end_id and if_end_id:
                        else_end_block = block_map.get(else_end_id)
                        if else_end_block:
                            else_end_statements = else_end_block.get("statements", [])
                            else_end_has_jump = False
                            if else_end_statements:
                                last_stmt = else_end_statements[-1]
                                if any(keyword in last_stmt for keyword in ["return", "break", "continue", "goto"]):
                                    else_end_has_jump = True
                            
                            if not else_end_has_jump and else_end_block.get("type") != "return":
                                edges.append({
                                    "source": else_end_id,
                                    "target": if_end_id,
                                    "type": "sequential",
                                    "condition": None
                                })
                                handled_blocks.add(else_end_id)
                                print(f"  Added else_end -> if_end edge: {else_end_id} -> {if_end_id}")
                elif then_ends_with_jump and if_end_id:
                    # Then branch ends with goto/return, and we know the block after if
                    # False branch should go to the block after the entire if statement
                    edges.append({
                        "source": condition_id,
                        "target": if_end_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (if_end, then ends with jump): {condition_id} -> {if_end_id}")
                elif then_ends_with_jump:
                    # Then branch ends with goto/return, but if_end_id not tracked
                    # Find the block that comes after the condition in the block sequence
                    # but is not part of the then branch
                    condition_index = next((i for i, b in enumerate(blocks) if b["node_id"] == condition_id), -1)
                    if condition_index >= 0:
                        # Look for the next block that's not in the then branch
                        for i in range(condition_index + 1, len(blocks)):
                            candidate_id = blocks[i]["node_id"]
                            # Skip if this is the then branch start or end
                            if candidate_id == then_start_id or candidate_id == then_end_id:
                                continue
                            # This should be the block after the if statement
                            edges.append({
                                "source": condition_id,
                                "target": candidate_id,
                                "type": "false_branch",
                                "condition": condition_expr
                            })
                            print(f"  Added false_branch (fallback, then ends with jump): {condition_id} -> {candidate_id}")
                            break
                elif then_end_id and if_end_id:
                    # No else branch, then doesn't end with jump
                    # False branch should go to if_end (after entire if statement), not then_end
                    edges.append({
                        "source": condition_id,
                        "target": if_end_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (if_end, no else): {condition_id} -> {if_end_id}")
                elif then_end_id:
                    # Fallback: if if_end_id not available, use then_end_id
                    edges.append({
                        "source": condition_id,
                        "target": then_end_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (after then, fallback): {condition_id} -> {then_end_id}")
                elif if_end_id:
                    # Fallback: use if_end_id if available
                    edges.append({
                        "source": condition_id,
                        "target": if_end_id,
                        "type": "false_branch",
                        "condition": condition_expr
                    })
                    print(f"  Added false_branch (if_end fallback): {condition_id} -> {if_end_id}")
        
        elif struct_type == "switch":
            # Switch: condition -> case labels based on value
            # Also need default case, and fallthrough handling
            condition_block = block_map.get(condition_id)
            if condition_block:
                condition_expr = condition_block.get("condition")
                case_labels = structure.get("case_labels", [])
                switch_end_id = structure.get("switch_end_id")
                
                # Resolve switch_end_id if needed
                if switch_end_id:
                     target_block = block_map.get(switch_end_id)
                     if not target_block:
                         # Find first block >= switch_end_id
                         for bid in sorted(block_map.keys()):
                             if bid >= switch_end_id:
                                 switch_end_id = bid
                                 break
                
                has_default = False
                
                for label in case_labels:
                    # Find the node ID for this label
                    label_line = label.get("line")
                    label_value = label.get("value")
                    label_type = "default" if label_value == "default" else "case"
                    
                    # Prefer recorded node_id if available, fallback to line search
                    target_block_id = label.get("node_id")
                    if target_block_id is None:
                        for b in blocks:
                            if b.get("type") == label_type and b.get("start_line") == label_line:
                                target_block_id = b["node_id"]
                                break
                    if target_block_id is None:
                        print(
                            f"DEBUG: Missing block for switch case value={label_value} line={label_line} "
                            f"from switch node {condition_id}"
                        )
                    
                    if target_block_id is not None:
                        # Prevent duplicate edges
                        edge_exists = any(
                            e["source"] == condition_id and e["target"] == target_block_id
                            for e in edges
                        )
                        if not edge_exists:
                            edges.append({
                                "source": condition_id,
                                "target": target_block_id,
                                "type": "switch_case",
                                "condition": label_value if label_value != "default" else "default"
                            })
                            print(f"  Added switch_case edge: {condition_id} -> {target_block_id} (value: {label_value})")
                        
                        if label_value == "default":
                            has_default = True
                        
                handled_blocks.add(condition_id)
                
                # If no default case, add edge to switch_end (fallthrough)
                if not has_default and switch_end_id:
                    edges.append({
                        "source": condition_id,
                        "target": switch_end_id,
                        "type": "switch_case",
                        "condition": "default"
                    })
                    print(f"  Added implicit default edge: {condition_id} -> {switch_end_id}")
        
        elif struct_type in ["while", "for"]:
            # Loop: condition -> body (true) or exit (false)
            condition_block = block_map.get(condition_id)
            if condition_block:
                condition_expr = condition_block.get("condition")
                
                body_start_id = structure.get("body_start_id")
                body_end_id = _find_block_after(blocks, body_start_id) if body_start_id else None
                loop_exit_id = structure.get("loop_exit_id")  # Get loop exit from structure_map
                
                # If loop_exit_id is a future node ID (not yet created), find the actual block
                if loop_exit_id:
                    # Check if this node ID exists in blocks
                    exit_block = next((b for b in blocks if b["node_id"] == loop_exit_id), None)
                    if not exit_block:
                        # Node doesn't exist yet, find the first block after the loop entry
                        condition_index = next((i for i, b in enumerate(blocks) if b["node_id"] == condition_id), -1)
                        if condition_index >= 0 and condition_index < len(blocks) - 1:
                            # Find the next block that is not part of the loop body
                            for i in range(condition_index + 1, len(blocks)):
                                candidate_id = blocks[i]["node_id"]
                                # Skip if this is the loop body start
                                if candidate_id == body_start_id:
                                    continue
                                # This should be the block after the loop
                                loop_exit_id = candidate_id
                                break
                        else:
                            loop_exit_id = None
                
                # True branch: condition -> loop body
                if body_start_id:
                    edges.append({
                        "source": condition_id,
                        "target": body_start_id,
                        "type": "loop_body",
                        "condition": condition_expr
                    })
                    
                    # False branch: condition -> loop exit (skip loop)
                    if loop_exit_id:
                        edges.append({
                            "source": condition_id,
                            "target": loop_exit_id,
                            "type": "false_branch",
                            "condition": condition_expr
                        })
                    
                    handled_blocks.add(condition_id)
                    
                    # Body end -> back to condition
                    if body_end_id:
                        edges.append({
                            "source": body_end_id,
                            "target": condition_id,
                            "type": "loop_continue",
                            "condition": None
                        })
        
        elif struct_type == "do":
            # Do-while: body always executes first, then condition check
            condition_block = block_map.get(condition_id)
            if condition_block:
                condition_expr = condition_block.get("condition")
                
                body_start_id = structure.get("body_start_id")
                body_end_id = condition_id  # Condition comes after body
                
                # Body -> condition
                if body_start_id:
                    edges.append({
                        "source": body_end_id,
                        "target": body_start_id,
                        "type": "loop_continue",
                        "condition": None
                    })
                    handled_blocks.add(body_end_id)
                
                # Condition -> body (true) or exit (false)
                next_block_id = _find_block_after(blocks, condition_id)
                if body_start_id:
                    edges.append({
                        "source": condition_id,
                        "target": body_start_id,
                        "type": "loop_body",
                        "condition": condition_expr
                    })
                    handled_blocks.add(condition_id)
    
    # Build sequential edges between consecutive blocks (skip those handled by control structures)
    for i in range(len(blocks) - 1):
        current_block = blocks[i]
        next_block = blocks[i + 1]
        current_id = current_block["node_id"]
        next_id = next_block["node_id"]
        
        # Skip if already handled by control structure
        if current_id in handled_blocks:
            continue
        
        # Skip if current block ends with return/break/continue/goto
        if current_block.get("type") == "return":
            continue
        
        statements = current_block.get("statements", [])
        is_label_block = current_block.get("type") in ["case", "default", "label"]
        if statements and not is_label_block:
            last_stmt = statements[-1]
            if any(keyword in last_stmt for keyword in ["return", "break", "continue", "goto"]):
                continue
        
        # Skip if there's already an edge from this block
        if any(e["source"] == current_id for e in edges):
            continue
        
        # Skip if next block is an else keyword block (statements == ["else"])
        # This prevents creating sequential edges from if branch to else branch
        next_statements = next_block.get("statements", [])
        if next_statements == ["else"]:
            # This is an else keyword block - don't create sequential edge to it
            # The else branch should only be reached via false_branch edge from the if condition
            continue
            
        # Check if current block is the end of a switch case that falls through (not common if next block is unrelated)
        # But wait, sequential edges connect i to i+1.
        # If block i is a case block (with statements), and block i+1 is the NEXT case or the switch end.
        # This is correct for fallthrough.
        # BUT if block i+1 is something completely different (e.g. exit node? No, blocks list doesn't have exit).
        
        # Add sequential edge
        edges.append({
            "source": current_id,
            "target": next_id,
            "type": "sequential",
            "condition": None
        })
    
    print(f"DEBUG: _build_cfg_edges summary: {len(edges)} total edges built")
    print(f"  Control structure edges: {len([e for e in edges if e.get('type') not in ['sequential', 'goto']])}")
    print(f"  Goto edges: {len([e for e in edges if e.get('type') == 'goto'])}")
    print(f"  Sequential edges: {len([e for e in edges if e.get('type') == 'sequential'])}")
    
    return edges


def _find_block_after(blocks: List[Dict[str, Any]], start_id: Optional[int]) -> Optional[int]:
    """Finds the first block that comes after the given block ID.
    
    Args:
        blocks: List of block dictionaries
        start_id: Starting block ID
        
    Returns:
        Block ID of the next block, or None if not found
    """
    if start_id is None:
        return None
    
    found = False
    for i, block in enumerate(blocks):
        if found:
            return block["node_id"]
        if block["node_id"] == start_id:
            found = True
    
    # If start_id is the last block, return None
    return None


def _find_exit_nodes(blocks: List[Dict[str, Any]], body_node) -> List[Dict[str, Any]]:
    """Finds exit nodes (blocks ending with return statements).
    
    Args:
        blocks: List of basic block dictionaries
        body_node: Function body node
        
    Returns:
        List of exit block dictionaries
    """
    exit_nodes = []
    
    for block in blocks:
        if block.get("type") == "return":
            exit_nodes.append(block)
        else:
            statements = block.get("statements", [])
            if statements:
                last_stmt = statements[-1]
                # Only treat as return if it starts with "return " or is exactly "return;"
                # Previous check 'if "return" in last_stmt' was too broad (matched "fail_return")
                # Also handle cases like "return(0);"
                
                # Simple check for return statement at end of block
                stmt_stripped = last_stmt.strip()
                if stmt_stripped.startswith("return") and not stmt_stripped.startswith("return_"):
                     # Ensure it's a statement, not part of a variable name (like return_val)
                     # Check if followed by space, (, or ;
                     if stmt_stripped == "return" or stmt_stripped.startswith("return ") or stmt_stripped.startswith("return(") or stmt_stripped.startswith("return;"):
                         exit_nodes.append(block)
    
    return exit_nodes


def find_all_paths_in_cfg(function_name: str, start_line, target_line) -> Optional[List[List[Dict[str, Any]]]]:
    """Finds all paths from a starting line to a target line in a function's control flow graph.
    
    Args:
        function_name: Name of the function
        start_line: Starting line number (int) or location string (e.g., "filename:line" or "839")
        target_line: Target line number (int) or location string (e.g., "filename:line" or "945")
        
    Returns:
        List of paths, where each path is a list of dictionaries representing nodes and edges.
        Each dictionary contains:
        - "node": node information (id, type, location, statements)
        - "edge": edge information (type, condition) if there's an edge to next node
        Returns None if the function or lines cannot be found.
    """
    # Extract line numbers if strings are provided
    def extract_line_number(line_input):
        if isinstance(line_input, int):
            return line_input
        if isinstance(line_input, str):
            # Try format "filename:line"
            if ":" in line_input:
                try:
                    return int(line_input.split(":")[-1])
                except ValueError:
                    pass
            # Try direct integer string
            try:
                return int(line_input)
            except ValueError:
                pass
        return None
    
    start_line_num = extract_line_number(start_line)
    target_line_num = extract_line_number(target_line)
    
    if start_line_num is None:
        logging.error(f"Invalid start_line format: {start_line}. Expected int or string like 'filename:line' or 'line'")
        return None
    if target_line_num is None:
        logging.error(f"Invalid target_line format: {target_line}. Expected int or string like 'filename:line' or 'line'")
        return None
    
    # Get CFG for the function
    cfg = get_cfg_by_function_name(function_name)
    if not cfg:
        logging.error(f"Failed to get CFG for function {function_name}")
        return None
    
    nodes = cfg.get("nodes", [])
    edges = cfg.get("edges", [])
    
    # Find nodes containing the start and target lines
    # Exclude entry/exit nodes as they have incorrect line numbers
    start_nodes = _find_nodes_by_line(nodes, start_line_num, exclude_types=["entry", "exit"])
    target_nodes = _find_nodes_by_line(nodes, target_line_num, exclude_types=["entry", "exit"])
    
    if not start_nodes:
        logging.error(f"No node found containing line {start_line_num} in function {function_name}")
        # Debug: show all nodes to diagnose the issue
        print(f"DEBUG: Searching for line {start_line_num}, but no node found.")
        print(f"DEBUG: All nodes in function (excluding entry/exit):")
        available_lines = [(n["node_id"], n.get("type"), n.get("start_line"), n.get("end_line"), n.get("location")) 
                          for n in nodes if n.get("type") not in ["entry", "exit"]]
        # Show nodes near the target line
        nearby_nodes = [(nid, t, sl, el, loc) for nid, t, sl, el, loc in available_lines 
                       if abs(sl - start_line_num) <= 10 or abs(el - start_line_num) <= 10]
        if nearby_nodes:
            print(f"DEBUG: Nodes near line {start_line_num} (within 10 lines):")
            for nid, t, sl, el, loc in sorted(nearby_nodes, key=lambda x: x[2]):
                print(f"  Node {nid} [{t}] lines {sl}-{el} at {loc}")
        else:
            print(f"DEBUG: No nodes found within 10 lines of {start_line_num}")
            print(f"DEBUG: Showing first 20 nodes in function:")
            for nid, t, sl, el, loc in available_lines[:20]:
                print(f"  Node {nid} [{t}] lines {sl}-{el} at {loc}")
        return None
    if not target_nodes:
        logging.error(f"No node found containing line {target_line_num} in function {function_name}")
        # Debug: show available nodes
        available_lines = [(n["node_id"], n.get("type"), n.get("start_line"), n.get("end_line"), n.get("location")) 
                          for n in nodes if n.get("type") not in ["entry", "exit"]]
        logging.debug(f"Available nodes (excluding entry/exit): {available_lines[:10]}...")
        return None
    
    # Debug: show found nodes
    print(f"DEBUG: Found {len(start_nodes)} start node(s) for line {start_line_num}:")
    for n in start_nodes:
        print(f"  Node {n['node_id']} [{n.get('type')}] at {n.get('location')} (lines {n.get('start_line')}-{n.get('end_line')})")
    print(f"DEBUG: Found {len(target_nodes)} target node(s) for line {target_line_num}:")
    for n in target_nodes:
        print(f"  Node {n['node_id']} [{n.get('type')}] at {n.get('location')} (lines {n.get('start_line')}-{n.get('end_line')})")
    
    # Build adjacency list from edges (include ALL edges including sequential for path finding)
    graph = {}
    edge_map = {}  # (source, target) -> edge info
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        edge_type = edge.get("type", "sequential")
        
        # Include ALL edge types for path finding (sequential edges are needed for complete paths)
        if source not in graph:
            graph[source] = []
        if target not in graph[source]:  # Avoid duplicate edges
            graph[source].append(target)
        edge_map[(source, target)] = edge
    
    # Debug: output graph information
    print(f"\nDEBUG: Graph adjacency list (total {len(graph)} nodes with outgoing edges):")
    for node_id in sorted(graph.keys()):
        node_info = next((n for n in nodes if n["node_id"] == node_id), None)
        node_desc = f"{node_info.get('type', 'unknown')} at {node_info.get('location', 'unknown')}" if node_info else "unknown"
        print(f"  Node {node_id} [{node_desc}] -> {graph[node_id]}")
    
    print(f"\nDEBUG: All edges (total {len(edges)}):")
    for edge in edges:
        source_node = next((n for n in nodes if n["node_id"] == edge.get("source")), None)
        target_node = next((n for n in nodes if n["node_id"] == edge.get("target")), None)
        source_desc = f"{source_node.get('type', 'unknown')} at {source_node.get('location', 'unknown')}" if source_node else "unknown"
        target_desc = f"{target_node.get('type', 'unknown')} at {target_node.get('location', 'unknown')}" if target_node else "unknown"
        edge_type = edge.get("type", "unknown")
        condition = edge.get("condition", "")
        cond_str = f" [{condition[:40]}...]" if condition and len(condition) > 40 else f" [{condition}]" if condition else ""
        print(f"  {edge.get('source')} [{source_desc}] -> {edge.get('target')} [{target_desc}] [{edge_type}]{cond_str}")
    
    # Find all paths from any start node to any target node
    all_paths = []
    target_node_ids = {node["node_id"] for node in target_nodes}
    
    for start_node in start_nodes:
        start_id = start_node["node_id"]
        print(f"DEBUG: Starting DFS from node {start_id}")
        paths = _find_all_paths_dfs(start_id, target_node_ids, graph, nodes, edge_map, max_depth=100)
        print(f"DEBUG: Found {len(paths)} path(s) from node {start_id}")
        all_paths.extend(paths)
    
    # Remove duplicate paths
    unique_paths = _remove_duplicate_paths(all_paths)
    
    return unique_paths if unique_paths else None


def _find_nodes_by_line(nodes: List[Dict[str, Any]], line_number: int, exclude_types: List[str] = None) -> List[Dict[str, Any]]:
    """Finds all nodes that contain the given line number.
    
    Args:
        nodes: List of node dictionaries
        line_number: Target line number
        exclude_types: List of node types to exclude (e.g., ["entry", "exit"])
        
    Returns:
        List of nodes that contain this line number
    """
    if exclude_types is None:
        exclude_types = []
    
    matching_nodes = []
    for node in nodes:
        node_type = node.get("type", "")
        if node_type in exclude_types:
            continue
            
        start_line = node.get("start_line", 0)
        end_line = node.get("end_line", 0)
        # Only match if the line is within the node's line range
        # For nodes with same start and end line, only match if exactly equal
        if start_line == end_line:
            if start_line == line_number:
                matching_nodes.append(node)
        else:
            if start_line <= line_number <= end_line:
                matching_nodes.append(node)
    
    # Sort by specificity: prefer nodes with smaller range that contain the line
    # Nodes where the line is closer to the start are preferred
    matching_nodes.sort(key=lambda n: (
        n.get("end_line", 0) - n.get("start_line", 0),  # Smaller range first
        abs(n.get("start_line", 0) - line_number)  # Closer to start line first
    ))
    
    return matching_nodes


def _find_all_paths_dfs(start_id: int, target_ids: Set[int], graph: Dict[int, List[int]], 
                        nodes: List[Dict[str, Any]], edge_map: Dict, 
                        visited: Set[int] = None, current_path: List[Dict[str, Any]] = None,
                        max_depth: int = 100, max_paths: int = 1000) -> List[List[Dict[str, Any]]]:
    """Uses DFS to find all paths from start to any target node.
    
    Args:
        start_id: Starting node ID
        target_ids: Set of target node IDs
        graph: Adjacency list representation of the graph
        nodes: List of all node dictionaries
        edge_map: Map from (source, target) to edge info
        visited: Set of visited nodes in current path (to detect cycles in current path)
        current_path: Current path being explored
        max_depth: Maximum path depth to prevent infinite loops
        max_paths: Maximum number of paths to find (to prevent explosion)
        
    Returns:
        List of paths, each path is a list of dictionaries with node and edge info
    """
    if visited is None:
        visited = set()
    if current_path is None:
        current_path = []
    
    # Check depth limit
    if len(current_path) >= max_depth:
        return []
    
    # Check if we've reached a target
    if start_id in target_ids:
        # Create a copy of current path with the target node
        node_map = {node["node_id"]: node for node in nodes}
        if start_id in node_map:
            final_path = current_path + [{"node": node_map[start_id], "edge": None}]
            return [final_path]
        return []
    
    # Check for cycles in current path (prevent infinite loops within same path)
    # But allow revisiting nodes in different paths
    if start_id in visited:
        return []  # Skip paths that form cycles within the same path
    
    # Get node info
    node_map = {node["node_id"]: node for node in nodes}
    if start_id not in node_map:
        return []
    
    current_node = node_map[start_id]
    paths = []
    
    # Mark current node as visited for this path
    new_visited = visited.copy()
    new_visited.add(start_id)
    
    # Check if current node is a loop entry node
    node_type = current_node.get("type", "")
    control_structure = current_node.get("control_structure", "")
    is_loop_entry = (node_type == "loop_entry")
    is_while_or_for = (control_structure in ["while", "for"])
    is_do_while = (control_structure == "do")
    
    # Explore neighbors
    neighbors = graph.get(start_id, [])
    if not neighbors:
        print(f"DEBUG: Node {start_id} has no outgoing edges")
    
    # For loop nodes, filter and process edges specially
    if is_loop_entry:
        loop_body_edges = []
        loop_continue_edges = []
        other_edges = []
        
        # Categorize edges
        for neighbor_id in neighbors:
            edge_info = edge_map.get((start_id, neighbor_id), {})
            edge_type = edge_info.get("type", "unknown") if edge_info else "unknown"
            
            if edge_type == "loop_body":
                loop_body_edges.append((neighbor_id, edge_info))
            elif edge_type == "loop_continue":
                loop_continue_edges.append((neighbor_id, edge_info))
            else:
                other_edges.append((neighbor_id, edge_info))
        
        # Process edges based on loop type
        if is_while_or_for:
            # while/for: two paths - enter loop once OR skip loop
            # Path 1: Enter loop body once (then skip loop_continue)
            for neighbor_id, edge_info in loop_body_edges:
                # Mark loop as visited to prevent going through loop_continue back
                loop_visited = new_visited.copy()
                loop_visited.add(start_id)  # Mark loop entry as visited
                
                path_entry = {
                    "node": current_node,
                    "edge": edge_info
                }
                
                # Recursively find paths, but skip loop_continue edges when we encounter the loop again
                neighbor_paths = _find_all_paths_dfs(
                    neighbor_id, target_ids, graph, nodes, edge_map,
                    loop_visited, current_path + [path_entry], max_depth
                )
                
                if neighbor_paths:
                    print(f"DEBUG: Found {len(neighbor_paths)} path(s) via loop_body edge {start_id}->{neighbor_id}")
                paths.extend(neighbor_paths)
            
            # Path 2: Skip loop (use other edges like sequential/false branch)
            for neighbor_id, edge_info in other_edges:
                path_entry = {
                    "node": current_node,
                    "edge": edge_info
                }
                
                neighbor_paths = _find_all_paths_dfs(
                    neighbor_id, target_ids, graph, nodes, edge_map,
                    new_visited, current_path + [path_entry], max_depth
                )
                
                if neighbor_paths:
                    print(f"DEBUG: Found {len(neighbor_paths)} path(s) via skip-loop edge {start_id}->{neighbor_id}")
                paths.extend(neighbor_paths)
        
        elif is_do_while:
            # do-while: one path - enter loop body once (then skip loop_continue)
            for neighbor_id, edge_info in loop_body_edges:
                # Mark loop as visited to prevent going through loop_continue back
                loop_visited = new_visited.copy()
                loop_visited.add(start_id)  # Mark loop entry as visited
                
                path_entry = {
                    "node": current_node,
                    "edge": edge_info
                }
                
                # Recursively find paths, but skip loop_continue edges when we encounter the loop again
                neighbor_paths = _find_all_paths_dfs(
                    neighbor_id, target_ids, graph, nodes, edge_map,
                    loop_visited, current_path + [path_entry], max_depth
                )
                
                if neighbor_paths:
                    print(f"DEBUG: Found {len(neighbor_paths)} path(s) via do-while loop_body edge {start_id}->{neighbor_id}")
                paths.extend(neighbor_paths)
        
    else:
        # Non-loop node: process all edges normally, but skip loop_continue if loop already visited
        for neighbor_id in neighbors:
            edge_info = edge_map.get((start_id, neighbor_id), {})
            edge_type = edge_info.get("type", "unknown") if edge_info else "unknown"
            
            # Skip loop_continue edge if we've already visited the target loop node
            if edge_type == "loop_continue":
                # Check if target node (which should be a loop_entry) is already in visited
                target_node = next((n for n in nodes if n["node_id"] == neighbor_id), None)
                if target_node and target_node.get("type") == "loop_entry":
                    if neighbor_id in visited:
                        # Already visited this loop, skip the continue edge
                        print(f"DEBUG: Skipping loop_continue edge {start_id}->{neighbor_id} (loop already visited)")
                        continue
            
            path_entry = {
                "node": current_node,
                "edge": edge_info if edge_info else None
            }
            
            # Recursively find paths from neighbor
            neighbor_paths = _find_all_paths_dfs(
                neighbor_id, target_ids, graph, nodes, edge_map,
                new_visited, current_path + [path_entry], max_depth
            )
            
            if neighbor_paths:
                print(f"DEBUG: Found {len(neighbor_paths)} path(s) via edge {start_id}->{neighbor_id} [{edge_type}]")
            paths.extend(neighbor_paths)
    
    return paths


def _remove_duplicate_paths(paths: List[List[Dict[str, Any]]]) -> List[List[Dict[str, Any]]]:
    """Removes duplicate paths based on node ID sequences.
    
    Args:
        paths: List of paths
        
    Returns:
        List of unique paths
    """
    seen = set()
    unique_paths = []
    
    for path in paths:
        # Create a signature from node IDs
        node_ids = tuple(entry["node"]["node_id"] for entry in path if "node" in entry)
        if node_ids not in seen:
            seen.add(node_ids)
            unique_paths.append(path)
    
    return unique_paths


def find_all_paths_between_lines(function_name: str, start_location: str, target_location: str) -> Optional[List[List[Dict[str, Any]]]]:
    """Finds all paths between two source locations in a function's CFG.
    
    Args:
        function_name: Name of the function
        start_location: Starting location in format 'filename:line_number' or just line number
        target_location: Target location in format 'filename:line_number' or just line number
        
    Returns:
        List of paths, where each path contains node and edge information.
        Returns None if paths cannot be found.
    """
    # Extract line numbers from locations
    def extract_line(location: str) -> Optional[int]:
        if isinstance(location, int):
            return location
        if isinstance(location, str):
            # Try format "filename:line"
            if ":" in location:
                try:
                    return int(location.split(":")[-1])
                except ValueError:
                    pass
            # Try direct integer
            try:
                return int(location)
            except ValueError:
                pass
        return None
    
    start_line = extract_line(start_location)
    target_line = extract_line(target_location)
    
    if start_line is None:
        logging.error(f"Invalid start_location format: {start_location}")
        return None
    if target_line is None:
        logging.error(f"Invalid target_location format: {target_location}")
        return None
    
    return find_all_paths_in_cfg(function_name, start_line, target_line)


def find_lvalue_key_svfgnode(location: str, eq_position: str) -> List[Dict[str, Any]]:
    """Finds key value flow operations for a specific lvalue using the backend graph-reader.
    
    Args:
        location: The source location of the lvalue, format "filename:line".
        eq_position: The position of the lvalue in the expression.
        
    Returns:
        A list of key SVFG nodes representing value flow operations.
    """
    command_caller = CommandCaller()
    query = {
        "command": "find-lvalue-key_svfgnode",
        "location": location,
        "eq_position": str(eq_position)
    }
    
    try:
        res = command_caller.send_query(query)
        if res:
            res_json = json.loads(res)
            # Check for error in response
            if isinstance(res_json, dict) and "error" in res_json:
                logging.error(f"Error in find_lvalue_key_svfgnode: {res_json['error']}")
                return []
            
            key_svfgs = res_json.get("key_svfgs", [])
            return key_svfgs
    except Exception as e:
        logging.error(f"Exception in find_lvalue_key_svfgnode: {e}")
        return []
    
    return []


def find_return_locations(function_name: str) -> List[str]:
    """Finds all return locations for a given function name using backend.
    
    Args:
        function_name: Name of the function.
        
    Returns:
        List of return locations in 'filename:line' format.
    """
    command_caller = CommandCaller()
    query = {
        "command": "show-return-locations",
        "name": function_name
    }
    
    try:
        res = command_caller.send_query(query)
        if res:
            res_json = json.loads(res)
            # Check for error in response
            if isinstance(res_json, dict) and "error" in res_json:
                logging.error(f"Error in find_return_locations: {res_json['error']}")
                return []
            
            return_locations_data = res_json.get("return_locations", [])
            locations = set()
            for item in return_locations_data:
                loc = item.get("location")
                if loc:
                    locations.add(loc)
            
            # Also add implicit return at function end (if possible)
            # This handles cases where execution falls off the end of the function (void or missing return)
            # which might not be explicitly listed by backend as a "return statement"
            func_info = find_function_body(function_name)
            if func_info:
                filename = func_info.get("filename")
                end_line = func_info.get("end_line")
                if filename and end_line:
                    locations.add(f"{filename}:{end_line}")
                    
            return list(locations)
    except Exception as e:
        logging.error(f"Exception in find_return_locations: {e}")
        return []
    
    return []


def trace_paths_to_exit(location: str, eq_position: str) -> List[List[Dict[str, Any]]]:
    """Generates filtered paths from a start location to the function exit.
    
    Args:
        location: Start location 'filename:line'.
        eq_position: Position of lvalue in the expression.
        
    Returns:
        List of filtered paths, containing only key value operations, branches, and start/end nodes.
    """
    # 1. Identify current function
    func_info = find_current_function(location)
    if not func_info or "error" in func_info:
        logging.error(f"Could not find function for location {location}")
        return []
    
    function_name = func_info.get("function_name")
    
    # 2. Get target return locations
    return_locs = find_return_locations(function_name)
    if not return_locs:
        logging.warning(f"No return locations found for {function_name}")
        return []
        
    # 3. Get key value operations
    key_ops = find_lvalue_key_svfgnode(location, eq_position)
    # Create a set of key locations for fast lookup
    key_locs = set()
    for op in key_ops:
        loc = op.get("location")
        if loc:
            key_locs.add(loc)
            
    # 4. Find all paths to each return location
    all_raw_paths = []
    for ret_loc in return_locs:
        paths = find_all_paths_between_lines(function_name, location, ret_loc)
        if paths:
            all_raw_paths.extend(paths)
            
    if not all_raw_paths:
        return []

    # 5. Cluster paths by Key SVFG Node sequence (based on location)
    # We also include the return location in the key to ensure paths in a cluster end at the same place
    clusters = defaultdict(list)
    
    for path in all_raw_paths:
        if not path:
            continue
            
        # Extract sequence of key nodes (by location)
        key_seq = []
        for step in path:
            node = step.get("node", {})
            loc = node.get("location")
            edge = step.get("edge")
            
            # Key ops from backend
            if loc in key_locs:
                key_seq.append(loc)
            # Add goto statements as key nodes
            elif edge and edge.get("type") == "goto":
                key_seq.append(f"goto:{loc}")
        
        # Add return location to the key
        end_node = path[-1].get("node", {})
        ret_loc = end_node.get("location")
        
        # Create cluster key
        cluster_key = tuple(key_seq) + (ret_loc,)
        clusters[cluster_key].append(path)
        
    final_filtered_paths = []
    
    # 6. Process each cluster
    for cluster_key, group in clusters.items():
        if not group:
            continue
            
        base_path = group[0]
        consistent_branches = set()
        
        # Identify candidate branches from the base path
        # A branch is a node where the edge type is one of the branch types
        base_branches = [] 
        for step in base_path:
            edge = step.get("edge")
            if edge and edge.get("type") in ["true_branch", "false_branch", "switch_case", "loop_body", "loop_continue"]:
                base_branches.append(step)
        
        # Check consistency against all other paths in group
        for branch_step in base_branches:
            node_id = branch_step["node"]["node_id"]
            edge_type = branch_step["edge"]["type"]
            # For switch_case, also get the condition value to distinguish different cases
            edge_condition = branch_step["edge"].get("condition") if edge_type == "switch_case" else None
            
            is_consistent = True
            for other_path in group[1:]:
                # Find this node in other_path
                found = False
                for other_step in other_path:
                    if other_step["node"]["node_id"] == node_id:
                        # Check edge type
                        other_edge = other_step.get("edge")
                        if other_edge and other_edge.get("type") == edge_type:
                            # For switch_case, also check that the condition matches
                            if edge_type == "switch_case":
                                if other_edge.get("condition") == edge_condition:
                                    found = True
                            else:
                                found = True
                        break
                if not found:
                    is_consistent = False
                    break
            
            if is_consistent:
                consistent_branches.add(node_id)

        # 7. Construct Representative Path from Base Path
        filtered_path = []
        start_node = base_path[0]["node"]
        end_node = base_path[-1]["node"]

        for step in base_path:
            node = step["node"]
            node_id = node["node_id"]
            node_loc = node.get("location")
            edge = step.get("edge")
            
            keep = False
            
            # Keep Start
            if node == start_node:
                keep = True
            # Keep Return
            elif node == end_node:
                keep = True
            # Keep Key Nodes
            elif node_loc in key_locs:
                keep = True
            # Keep Goto Statements
            elif edge and edge.get("type") == "goto":
                keep = True
            # Keep Consistent Branches
            elif node_id in consistent_branches:
                keep = True
            
            if keep:
                filtered_path.append(step)
        
        if filtered_path:
            final_filtered_paths.append(filtered_path)
            
    return final_filtered_paths


if __name__ == '__main__':
    # # Test find_lvalue_key_svfgnode
    # print("\n" + "="*80)
    # print("Testing find_lvalue_key_svfgnode")
    # print("="*80)
    # # Example from user query: "tif_dirwrite.c:839", eq_position "8"
    # location = "tif_getimage.c:370"
    # eq_position = "18"
    # print(f"Finding key SVFG nodes for {location} at eq_pos {eq_position}...")
    # key_nodes = find_lvalue_key_svfgnode(location, eq_position)
    # print(f"Found {len(key_nodes)} key nodes:")
    # for node in key_nodes:
    #     print(f"  {node.get('node_type')}: {node.get('location')}")

    # # Test find_return_locations
    # print("\n" + "="*80)
    # print("Testing find_return_locations")
    # print("="*80)
    # # Using TIFFWriteDirectorySec as it is the function containing the example location
    # function_name = "TIFFRGBAImageBegin" 
    # print(f"Finding return locations for {function_name}...")
    # ret_locs = find_return_locations(function_name)
    # print(f"Found {len(ret_locs)} return locations:")
    # for loc in ret_locs:
    #     print(f"  {loc}")
    
    # print("\n" + "="*80)
    # print(f"Debug: Checking CFG nodes for return locations in {function_name}")
    # print("="*80)
    # cfg = get_cfg_by_function_name(function_name)
    # if cfg:
    #     nodes = cfg.get("nodes", [])
    #     for loc in ret_locs:
    #         try:
    #             line_num = int(loc.split(":")[-1])
    #             matching_nodes = _find_nodes_by_line(nodes, line_num)
    #             print(f"Location: {loc} (Line {line_num})")
    #             if matching_nodes:
    #                 for node in matching_nodes:
    #                     print(f"  Matched Node {node['node_id']} [{node.get('type')}] lines {node.get('start_line')}-{node.get('end_line')}")
    #                     if node.get('statements'):
    #                         print(f"    Statements: {node.get('statements')}")
    #             else:
    #                 print(f"  No matching CFG node found.")
    #         except Exception as e:
    #             print(f"  Error processing location {loc}: {e}")
    # else:
    #     print(f"Failed to get CFG for {function_name}")
        
    # # Test find_all_paths_between_lines
    # print("\n" + "="*80)
    # print("Testing find_all_paths_between_lines")
    # print("="*80)
    # location_line_start = "tif_dirread.c:1172"
    # location_line_end = "tif_dirread.c:1283"
    # function_name = "TIFFReadDirEntrySbyteArray"
    # print(f"Finding all paths between {location_line_start} and {location_line_end} in {function_name}...")
    # paths = find_all_paths_between_lines(function_name, location_line_start, location_line_end)
    # if paths:
    #     print(f"Found {len(paths)} paths:")
    #     for i, path in enumerate(paths, 1):
    #         print(f"\nPath {i} ({len(path)} steps):")
    #         for step in path:
    #             node = step.get("node", {})
    #             edge = step.get("edge")
    #             edge_info = ""
    #             if edge:
    #                 edge_info = f" -> [{edge.get('type')}]"
    #                 if edge.get('condition'):
    #                     edge_info += f" ({edge.get('condition')})"
    #             print(f"  Node {node.get('node_id')} [{node.get('type')}] at {node.get('location')}{edge_info}")
    # else:
    #     print("No paths found.")
        
    source_location_eq_position_list = [
        ("tif_dirread.c:1166", 6),
        ("tif_dirread.c:1519", 6),
        ("tif_dirread.c:1686", 6),
        ("tif_dirread.c:1855", 6),
        ("tif_dirread.c:2188", 6),
        ("tif_dirread.c:2323", 6),
        ("tif_dirread.c:2568", 6),
        ("tif_dirread.c:2797", 6),
        ("tif_dirread.c:4981", 9),
        ("tif_dirwrite.c:839", 8),
        ("tif_dirwrite.c:1688", 7),
        ("tif_dirwrite.c:1746", 7),
        ("tif_dirwrite.c:1934", 4),
        ("tif_getimage.c:370", 18),
        ("tif_jpeg.c:2057", 20),
        ("tif_read.c:1421", 20),
        ("tif_write.c:658", 6),
    ]
    
    location, eq_position = source_location_eq_position_list[1]

    # Test trace_paths_to_exit
    print("\n" + "="*80)
    print("Testing trace_paths_to_exit")
    print("="*80)
    # print(f"Tracing paths from {location} to exit in {function_name}...")
    paths = trace_paths_to_exit(location, eq_position)
    if paths:
        print(f"Found {len(paths)} filtered paths:")
        for i, path in enumerate(paths, 1):
            print(f"\nPath {i} ({len(path)} steps):")
            for step in path:
                node = step.get("node", {})
                edge = step.get("edge")
                edge_info = ""
                if edge:
                    edge_info = f" -> [{edge.get('type')}]"
                    if edge.get('condition'):
                        edge_info += f" ({edge.get('condition')})"
                print(f"  Node {node.get('node_id')} [{node.get('type')}] at {node.get('location')}{edge_info}")
    else:
        print("No paths found.")
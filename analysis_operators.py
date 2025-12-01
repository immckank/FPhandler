import os
import subprocess
import logging
import sys
import json
import re
import utils
from utils import *
from typing import List, Dict, Any, Optional, Set, Tuple
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
from function_ast_cfg import FunctionCFGAnalyzer, configure_function_cfg_dependencies

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

def _byte_offset_to_point(code_bytes: bytes, byte_index: int) -> Tuple[int, int]:
    """Convert a byte offset inside the function source to (line, column)."""
    if byte_index <= 0:
        return (0, 0)
    snippet = code_bytes[:byte_index].decode("utf8", errors="ignore")
    line = snippet.count("\n")
    last_newline = snippet.rfind("\n")
    column = len(snippet) if last_newline == -1 else len(snippet) - last_newline - 1
    return (line, column)

def _extract_lhs_identifier(left_node, code_bytes: bytes) -> Optional[str]:
    """Extract a plain identifier from assignment left-hand side."""
    if left_node is None:
        return None
    current = left_node
    while current.type == "parenthesized_expression":
        inner = current.child_by_field_name("expression")
        if inner is None:
            break
        current = inner
    if current.type == "identifier":
        return code_bytes[current.start_byte:current.end_byte].decode("utf8").strip()
    return None

def _collect_identifier_occurrences(node, code_bytes: bytes, context: str = "plain") -> List[Dict[str, str]]:
    """Collect identifier occurrences within an expression along with their context."""
    occurrences: List[Dict[str, str]] = []
    if node is None:
        return occurrences
    node_type = getattr(node, "type", "")
    if node_type == "identifier":
        name = code_bytes[node.start_byte:node.end_byte].decode("utf8").strip()
        if name:
            occurrences.append({"name": name, "context": context})
        return occurrences
    if node_type == "pointer_expression":
        children = list(node.children or [])
        if len(children) >= 2 and children[0].type in {"&", "*"}:
            operator = children[0].type
            operand = children[1]
            nested_context = "address_of" if operator == "&" else "dereference"
            occurrences.extend(_collect_identifier_occurrences(operand, code_bytes, nested_context))
            for extra in children[2:]:
                occurrences.extend(_collect_identifier_occurrences(extra, code_bytes, context))
            return occurrences
    for child in node.children:
        occurrences.extend(_collect_identifier_occurrences(child, code_bytes, context))
    return occurrences

def _extract_assignment_relation(node, code_bytes: bytes, function_start_line: int) -> Optional[Dict[str, Any]]:
    """Build alias relation metadata from a single assignment_expression node."""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    lhs_name = _extract_lhs_identifier(left, code_bytes)
    if not lhs_name:
        return None
    operator_segment = code_bytes[left.end_byte:right.start_byte]
    operator_text = operator_segment.decode("utf8", errors="ignore").strip()
    if operator_text != "=":
        return None
    relation = {
        "lhs": lhs_name,
        "rhs": _collect_identifier_occurrences(right, code_bytes),
        "operator_point": None,
    }
    eq_index = operator_segment.find(b"=")
    if eq_index != -1:
        eq_byte = left.end_byte + eq_index
        local_line, local_column = _byte_offset_to_point(code_bytes, eq_byte)
        relation["operator_point"] = (
            (function_start_line or 0) + local_line,
            local_column,
        )
    return relation

def _build_assignment_relations(tree_root, code_bytes: bytes, function_start_line: int) -> List[Dict[str, Any]]:
    """Traverse AST and collect simple '=' assignments within the function."""
    relations: List[Dict[str, Any]] = []
    def _walk(node):
        if node.type == "assignment_expression":
            relation = _extract_assignment_relation(node, code_bytes, function_start_line)
            if relation:
                relations.append(relation)
        for child in node.children:
            _walk(child)
    _walk(tree_root)
    return relations

def _select_assignment_relation(relations: List[Dict[str, Any]], target_line: int, target_column: Optional[int]) -> Optional[Dict[str, Any]]:
    """Pick the assignment relation that matches the given source location."""
    candidates = []
    for rel in relations:
        point = rel.get("operator_point")
        if not point:
            continue
        if point[0] == target_line:
            candidates.append(rel)
    if not candidates:
        return None
    if target_column is None:
        return candidates[0]
    for rel in candidates:
        point = rel.get("operator_point")
        if point and point[1] == target_column:
            return rel
    return min(candidates, key=lambda rel: abs(rel["operator_point"][1] - target_column))

def _extract_seed_from_line(code_line: Optional[str], eq_position: Optional[int]) -> Optional[str]:
    """Fallback extraction of the seed variable using raw code text."""
    if not isinstance(code_line, str):
        return None
    line = code_line.rstrip("\n")
    idx = None
    if isinstance(eq_position, int):
        if 0 <= eq_position < len(line) and line[eq_position] == "=":
            idx = eq_position
    if idx is None:
        idx = line.find("=")
    if idx == -1:
        return None
    lhs_fragment = line[:idx].rstrip()
    while lhs_fragment and lhs_fragment[-1] in "*&":
        lhs_fragment = lhs_fragment[:-1].rstrip()
    match = re.search(r"[A-Za-z_]\w*$", lhs_fragment)
    if match:
        return match.group(0)
    return normalize_identifier(lhs_fragment)

def get_alias_set(location: str, eq_position: int) -> List[str]:
    """
    Collect alias variables for the assignment located at (location, eq_position).

    Args:
        location: Source location in the form 'file:line'.
        eq_position: Column index of the '=' sign in the assignment line.

    Returns:
        List of variable names aliasing the seed variable（包含种子变量本身）.
    """
    if not isinstance(location, str) or ":" not in location:
        logging.warning("get_alias_set requires location in 'file:line' format.")
        return []
    try:
        target_line = int(location.split(":")[-1])
    except (ValueError, TypeError):
        logging.warning("get_alias_set unable to parse source line from %s", location)
        return []
    try:
        target_column = int(eq_position)
    except (ValueError, TypeError):
        target_column = None

    code_line = find_code_line(location, strip_whitespace=False)
    func_meta = find_current_function(location)
    if not func_meta or func_meta.get("error"):
        logging.warning("get_alias_set failed to locate function for %s", location)
        return []

    function_source = func_meta.get("function_body")
    if not isinstance(function_source, str) or not function_source.strip():
        logging.warning("get_alias_set received empty function body for %s", location)
        return []

    function_start_line = func_meta.get("start_line") or 0
    try:
        function_start_line = int(function_start_line)
    except (ValueError, TypeError):
        function_start_line = 0

    tree, code_bytes = _parse_function_ast(function_source)
    if tree is None or code_bytes is None:
        logging.warning("tree-sitter parser unavailable; cannot compute alias set.")
        return []

    relations = _build_assignment_relations(tree.root_node, code_bytes, function_start_line)
    if not relations:
        return []

    seed_relation = _select_assignment_relation(relations, target_line, target_column)
    seed_var = seed_relation.get("lhs") if seed_relation else None
    if not seed_var:
        seed_var = _extract_seed_from_line(code_line, target_column)
    if not seed_var:
        logging.warning("get_alias_set failed to resolve seed variable at %s (eq=%s)", location, eq_position)
        return []

    alias_set: Set[str] = {seed_var}
    changed = True
    while changed:
        changed = False
        for relation in relations:
            lhs = relation.get("lhs")
            if not lhs or lhs in alias_set:
                continue
            rhs_refs = relation.get("rhs") or []
            for ref in rhs_refs:
                if ref.get("context") != "plain":
                    continue
                if ref.get("name") in alias_set:
                    alias_set.add(lhs)
                    changed = True
                    break

    return sorted(alias_set)

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


'''
control flow graph (CFG)
'''
configure_function_cfg_dependencies(
    find_function_body=find_function_body,
    parse_function_ast=_parse_function_ast,
    dump_source_line=dump_source_line,
)


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
    analyzer = FunctionCFGAnalyzer.from_function_name(function_name)
    if analyzer is None:
        logging.error(f"Failed to prepare CFG analyzer for {function_name}")
        return None

    cfg = analyzer.build_cfg()
    if not cfg:
        logging.error(f"Failed to build CFG for function {function_name}")
        return None
    
    nodes = cfg.get("nodes", [])
    edges = cfg.get("edges", [])
    
    # Find nodes containing the start and target lines
    # Exclude entry/exit nodes as they have incorrect line numbers
    start_nodes = _find_nodes_by_line(nodes, start_line_num, exclude_types=["entry", "exit"])
    target_nodes = _find_nodes_by_line(nodes, target_line_num, exclude_types=["entry", "exit"])
    
    if not start_nodes:
        logging.error(f"No node found containing line {start_line_num} in function {function_name}")
        return None
    if not target_nodes:
        logging.error(f"No node found containing line {target_line_num} in function {function_name}")
        # Debug: show available nodes
        available_lines = [(n["node_id"], n.get("type"), n.get("start_line"), n.get("end_line"), n.get("location")) 
                          for n in nodes if n.get("type") not in ["entry", "exit"]]
        logging.debug(f"Available nodes (excluding entry/exit): {available_lines[:10]}...")
        return None
    
    
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
    
    # Find all paths from any start node to any target node
    all_paths = []
    target_node_ids = {node["node_id"] for node in target_nodes}
    
    for start_node in start_nodes:
        start_id = start_node["node_id"]
        paths = _find_all_paths_dfs(start_id, target_node_ids, graph, nodes, edge_map, max_depth=100)
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
    
    print(f"DEBUG: Key locations: {key_locs}")
            
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
    # analyzer = FunctionCFGAnalyzer.from_function_name(function_name)
    # cfg = analyzer.build_cfg() if analyzer else None
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
        
    # Test find_all_paths_between_lines
    # print("\n" + "="*80)
    # print("Testing find_all_paths_between_lines")
    # print("="*80)
    # location_line_start = "tif_dirread.c:2280"
    # location_line_end = "tif_dirread.c:2281"
    # function_name = "TIFFReadDirEntrySlong8Array"
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
    
    for location, eq_position in source_location_eq_position_list:
        print(f"Testing get_alias_set for {location} at eq_position {eq_position}")
        alias_set = get_alias_set(location, eq_position)
        print(f"Alias set: {alias_set}")
    
    # location, eq_position = source_location_eq_position_list[16]

    # # Test trace_paths_to_exit
    # print("\n" + "="*80)
    # print("Testing trace_paths_to_exit")
    # print("="*80)
    # # print(f"Tracing paths from {location} to exit in {function_name}...")
    # paths = trace_paths_to_exit(location, eq_position)
    # if paths:
    #     print(f"Found {len(paths)} filtered paths:")
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
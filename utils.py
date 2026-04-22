import os
from config import *
import config as _cfg
import logging
import datetime as _dt
import json
import re

def _sar_basename_stem():
    """SAR_PATH 去扩展名，用于日志文件名前缀；批处理可由 config.RUN_LOG_STEM 覆盖。"""
    stem = getattr(_cfg, "RUN_LOG_STEM", None)
    if stem:
        return stem
    return os.path.splitext(os.path.basename(_cfg.SAR_PATH))[0]


def _session_time_str():
    ts = getattr(_cfg, "RUN_SESSION_TIME_STR", None)
    if ts:
        return ts
    return _dt.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")


# 设置日志
def setup_logger(log_type):
    main_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    llm_formatter = logging.Formatter("%(message)s")
    time_str = _session_time_str()
    sar_stem = _sar_basename_stem()
    if log_type == "main":
        log_file_name = f"{sar_stem}-{time_str}.log"
        # 如果不存在os.path.join(RES_ROOT_PATH, "RUN")创建一个
        if not os.path.exists(os.path.join(RES_ROOT_PATH, "RUN")):
            os.makedirs(os.path.join(RES_ROOT_PATH, "RUN"))
        log_file_path = os.path.join(RES_ROOT_PATH, "RUN", log_file_name)
        logger = logging.getLogger("main")
        logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file_path, mode="w")
        file_handler.setFormatter(main_formatter)
        logger.addHandler(file_handler)
        return logger
    elif log_type == "result":
        log_file_name = f"result_{sar_stem}_{LLM_TYPE}-free-{time_str}.log"
        if not os.path.exists(os.path.join(RES_ROOT_PATH, "RESULT")):
            os.makedirs(os.path.join(RES_ROOT_PATH, "RESULT"))
        log_file_path = os.path.join(RES_ROOT_PATH, "RESULT", log_file_name)
        logger = logging.getLogger(f"result_{sar_stem}_{LLM_TYPE}")
        logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file_path, mode="a")
        file_handler.setFormatter(llm_formatter)
        logger.addHandler(file_handler)
        return logger
    elif log_type == "analysis":
        log_file_name = f"analysis_{sar_stem}_{LLM_TYPE}-free-{time_str}.log"
        if not os.path.exists(os.path.join(RES_ROOT_PATH, "TRACE")):
            os.makedirs(os.path.join(RES_ROOT_PATH, "TRACE"))
        log_file_path = os.path.join(RES_ROOT_PATH, "TRACE", log_file_name)
        logger = logging.getLogger(f"analysis_{sar_stem}_{LLM_TYPE}")
        logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file_path, mode="a")
        file_handler.setFormatter(llm_formatter)
        logger.addHandler(file_handler)
        return logger
    else:
        raise ValueError("Invalid log type")

# 找到指定项目中指定文件名的路径
# def find_file_path(file_name):
#     for root, dirs, files in os.walk(PROJECT_ROOT):
#         if file_name in files:
#             full_path = os.path.join(root, file_name)
#             return os.path.relpath(full_path, PROJECT_ROOT)
#     return None

def find_file_path(file_name):
    """
    找到指定项目中指定文件名的路径。
    
    支持两种输入格式：
    1. 简单文件名：如 "tiffcrop.c"
    2. 相对路径：如 "libtiff/tiffcrop.c" 或 "crypto/evp/e_des3.c"
    
    如果有多个同名文件，优先返回路径匹配度最高的那个。
    """
    # 提取文件名部分
    base_name = os.path.basename(file_name)
    
    # 提取传入的相对路径部分（用于匹配）
    input_dir = os.path.dirname(file_name) if os.sep in file_name or '/' in file_name else ""
    # 标准化路径分隔符
    input_dir = input_dir.replace('\\', '/').replace(os.sep, '/')
    
    # 兼容旧 SAR：路径可能带源码树根目录名前缀，去掉后与 PROJECT_ROOT 下相对路径一致
    _legacy_prefix = os.path.basename(PROJECT_ROOT) + '/'
    if input_dir.startswith(_legacy_prefix):
        input_dir = input_dir[len(_legacy_prefix):]
    
    # 搜索所有匹配的文件路径（相对 PROJECT_ROOT）
    matching_paths = []
    project_root = os.path.abspath(PROJECT_ROOT)
    if not os.path.isdir(project_root):
        return None
    for root, dirs, files in os.walk(project_root):
        if base_name in files:
            full_path = os.path.join(root, base_name)
            rel_path = os.path.relpath(full_path, project_root)
            matching_paths.append(rel_path)
    
    # 如果没找到任何匹配
    if not matching_paths:
        return None
    
    # 如果只有一个匹配，直接返回
    if len(matching_paths) == 1:
        return matching_paths[0]
    
    # 如果有多个匹配且传入的是路径，选择最匹配的
    # print(f"matching_paths: {matching_paths}")
    if input_dir:
        # 收集所有包含 input_dir 的匹配路径
        for path in list(matching_paths):  # 遍历副本，避免迭代中 remove 漏项
            normalized_path = path.replace('\\', '/').replace(os.sep, '/')
            if not normalized_path.endswith(input_dir + '/' + base_name):
                matching_paths.remove(path)
        if not matching_paths:
            return None
    
    return min(matching_paths, key=len)


# --- Location protocol: fl / ln / cl (structured) vs location string (LLM tool / legacy) ---

def parse_source_location_to_fl_ln(source_location):
    """
    Parse 'path/to/file.c:755' into {"fl", "ln"}; optional cl not in string form.
    Returns None if invalid. Used at LLM tool entry before send_query.
    """
    if not source_location or not isinstance(source_location, str):
        return None
    if ":" not in source_location:
        return None
    fl, ln_str = source_location.rsplit(":", 1)
    if not fl or not ln_str.isdigit():
        return None
    return {"fl": fl, "ln": int(ln_str)}


def source_loc_to_string(fl, ln):
    """fl + ln -> location string for find_code_line / dump_source_line."""
    return f"{fl}:{ln}"


def normalize_source_loc(source_loc):
    """
    Accept dict {"fl", "ln", "cl"?} or string; return dict with fl, ln, cl (cl may be None).
    """
    if source_loc is None:
        return None
    if isinstance(source_loc, dict):
        fl = source_loc.get("fl")
        ln = source_loc.get("ln")
        if fl is None or ln is None:
            return None
        cl = source_loc.get("cl")
        return {"fl": fl, "ln": int(ln), "cl": int(cl) if cl is not None else None}
    if isinstance(source_loc, str):
        d = parse_source_location_to_fl_ln(source_loc)
        if d:
            d["cl"] = None
        return d
    return None


def location_string_from_source_loc(source_loc):
    """Dict or str -> 'fl:ln' for APIs that still need a string."""
    d = normalize_source_loc(source_loc)
    if not d:
        return None
    return source_loc_to_string(d["fl"], d["ln"])


def find_code_line_fl_ln(fl, ln, strip_whitespace=True):
    """Read source line using structured fl/ln."""
    return find_code_line(source_loc_to_string(fl, ln), strip_whitespace)


def ensure_location_string(node):
    """
    If node has fl+ln but no location string, set node['location'] = 'fl:ln'.
    Mutates node in place; returns node.
    """
    if not isinstance(node, dict):
        return node
    if node.get("location"):
        return node
    fl = node.get("fl") or node.get("filename")
    ln = node.get("ln")
    if ln is None:
        ln = node.get("line")
    if fl is not None and ln is not None:
        node["location"] = source_loc_to_string(fl, int(ln))
    return node


# 根据指定scource_location找到对应的代码行
def find_code_line(source_location, strip_whitespace=True):
    file_name = source_location.split(":")[0]
    file_path = find_file_path(file_name)
    if file_path is None:
        return None
    file_path = os.path.join(os.path.abspath(PROJECT_ROOT), file_path)
    if not file_path:
        return None
    with open(file_path, 'r') as f:
        lines = f.readlines()
        line_number = int(source_location.split(":")[1]) - 1
        if line_number < 0 or line_number >= len(lines):
            return None
        return lines[line_number] if not strip_whitespace else lines[line_number].strip()

# 提取赋值表达式的左值变量名
def extract_lhs_variable(assignment):
    """
    从赋值表达式中提取左值变量名。
    
    处理情况：
    1. 简单赋值: x = 5 -> "x"
    2. 指针赋值: *ptr = value -> "ptr"
    3. 嵌套赋值: if ((value = func()) == NULL) -> "value"
    4. 无赋值: func(); -> None
    5. return语句: return func(); -> None
    
    Args:
        assignment: 赋值表达式字符串
        
    Returns:
        str: 变量名，如果不是赋值表达式则返回 None
    """
    if assignment is None or not isinstance(assignment, str):
        return None
    assignment = assignment.strip()
    
    # 检查是否是return语句（不是赋值）
    if assignment.startswith('return '):
        return None
    
    # 查找赋值运算符（排除 ==, !=, <=, >= 等比较运算符）
    # 需要找到真正的赋值 =，而不是比较运算符中的 =
    # 策略：找到所有可能的赋值位置，选择最合适的一个
    assign_candidates = []
    paren_depth = 0
    i = 0
    
    while i < len(assignment):
        c = assignment[i]
        
        if c == '(':
            paren_depth += 1
            i += 1
        elif c == ')':
            paren_depth -= 1
            i += 1
        elif c == '=':
            # 检查这是不是一个赋值运算符
            next_char = assignment[i + 1] if i + 1 < len(assignment) else ''
            prev_char = assignment[i - 1] if i > 0 else ''
            
            # 排除 ==, !=, <=, >=, +=, -=, *=, /= 等
            if next_char not in ['='] and prev_char not in ['!', '<', '>', '=', '+', '-', '*', '/', '%', '&', '|', '^']:
                # 记录候选位置和括号深度
                assign_candidates.append((i, paren_depth))
            i += 1
        else:
            i += 1
    
    # 没有找到赋值运算符
    if not assign_candidates:
        return None
    
    # 选择最合适的赋值位置：
    # 1. 优先选择括号深度为0的（最外层）
    # 2. 如果没有深度为0的，选择深度最大的（最内层，通常在条件语句的括号内）
    depth_zero = [pos for pos, depth in assign_candidates if depth == 0]
    if depth_zero:
        assign_pos = depth_zero[0]  # 第一个深度为0的
    else:
        # 选择深度最大的第一个
        max_depth = max(depth for _, depth in assign_candidates)
        assign_pos = next(pos for pos, depth in assign_candidates if depth == max_depth)
    
    # 提取左值部分
    lhs = assignment[:assign_pos].strip()
    
    # 移除外层的括号和if/while等关键字
    # 例如: "if ((value" -> "value"
    while True:
        lhs = lhs.strip()
        changed = False
        
        # 移除开头的关键字
        for keyword in ['if', 'while', 'for', 'switch']:
            if lhs.startswith(keyword + ' '):
                lhs = lhs[len(keyword):].strip()
                changed = True
                break
            if lhs.startswith(keyword + '('):
                lhs = lhs[len(keyword):].strip()
                changed = True
                break
        
        # 移除开头的单个左括号（如果没有匹配的右括号）
        # 这种情况出现在 "((value" 这样的左值中
        if lhs.startswith('('):
            lhs = lhs[1:].strip()
            changed = True
        
        if not changed:
            break
    
    # 现在lhs应该是类似 "value" 或 "*ptr" 或 "arr[0]" 的形式
    # 提取实际的变量名
    lhs = lhs.strip()
    
    # 移除类型声明（如果存在）
    # 例如: "int *ptr" -> "ptr", "char* str" -> "str"
    parts = lhs.split()
    if len(parts) > 1:
        # 最后一个部分通常是变量名
        lhs = parts[-1]
    
    # 移除前缀的 * (指针解引用)
    lhs = lhs.lstrip('*')
    
    # 移除数组下标 [...]
    if '[' in lhs:
        lhs = lhs[:lhs.index('[')]
    
    # 移除成员访问符号 -> 和 .
    if '->' in lhs:
        lhs = lhs.split('->')[-1]
    if '.' in lhs:
        lhs = lhs.split('.')[-1]
    
    lhs = lhs.strip()
    
    # 检查是否为有效的变量名（只包含字母、数字、下划线）
    if lhs and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', lhs):
        return lhs
    
    return None

# 获取赋值等号在代码行中的位置
def get_eq_position(assignment, preserve_whitespace=True):
    """
    找到赋值表达式中等号的字符位置。
    
    处理情况：
    1. 简单赋值: x = 5 -> 返回等号的索引
    2. 嵌套赋值: if ((value = func()) == NULL) -> 返回赋值等号的索引（不是比较等号）
    3. 无赋值: func(); -> 返回 None
    4. return语句: return func(); -> 返回 None
    
    Args:
        assignment: 赋值表达式字符串
        preserve_whitespace: 是否保留前导/尾随空白字符
            - False (默认): 移除前导空白，返回在stripped字符串中的位置
            - True: 保留前导空白，返回在原始字符串中的位置（能区分\t和空格）
        
    Returns:
        int: 等号在字符串中的位置索引（0-based），如果不是赋值表达式则返回 None
    """
    original_assignment = assignment
    
    if not preserve_whitespace:
        assignment = assignment.strip()
    
    # 检查是否是return语句（不是赋值）
    if assignment.lstrip().startswith('return '):
        return None
    
    # 查找赋值运算符（排除 ==, !=, <=, >= 等比较运算符）
    # 需要找到真正的赋值 =，而不是比较运算符中的 =
    # 策略：找到所有可能的赋值位置，选择最合适的一个
    assign_candidates = []
    paren_depth = 0
    i = 0
    
    while i < len(assignment):
        c = assignment[i]
        
        if c == '(':
            paren_depth += 1
            i += 1
        elif c == ')':
            paren_depth -= 1
            i += 1
        elif c == '=':
            # 检查这是不是一个赋值运算符
            next_char = assignment[i + 1] if i + 1 < len(assignment) else ''
            prev_char = assignment[i - 1] if i > 0 else ''
            
            # 排除 ==, !=, <=, >=, +=, -=, *=, /= 等
            if next_char not in ['='] and prev_char not in ['!', '<', '>', '=', '+', '-', '*', '/', '%', '&', '|', '^']:
                # 记录候选位置和括号深度
                assign_candidates.append((i, paren_depth))
            i += 1
        else:
            i += 1
    
    # 没有找到赋值运算符
    if not assign_candidates:
        return None
    
    # 选择最合适的赋值位置：
    # 1. 优先选择括号深度为0的（最外层）
    # 2. 如果没有深度为0的，选择深度最大的（最内层，通常在条件语句的括号内）
    depth_zero = [pos for pos, depth in assign_candidates if depth == 0]
    if depth_zero:
        assign_pos = depth_zero[0]  # 第一个深度为0的
    else:
        # 选择深度最大的第一个
        max_depth = max(depth for _, depth in assign_candidates)
        assign_pos = next(pos for pos, depth in assign_candidates if depth == max_depth)
    
    return assign_pos

# 提取SAR文件中的alter部分
def extract_alter(sar_path, sar_file_name):
    seperator = "#####"
    line_alter = 0

    # txt格式文件
    with open(os.path.join(sar_path, sar_file_name), 'r') as f:
        # 统计行总数
        # 找到最后一个以seperator开头的行
        line_total = 0
        for line in f:
            line_total += 1
            if line.startswith(seperator):
                line_alter = line_total
    # 从line_alter行开始提取到文件末尾
    with open(os.path.join(sar_path, sar_file_name), 'r') as f:
        extracted_lines = f.readlines()[line_alter:]
    # 保存到文件
    with open(os.path.join(sar_path, sar_file_name.replace('.txt', '_alter.txt')), 'w') as f:
        f.writelines(extracted_lines)
    return extracted_lines

def safe_load_json(s: str):
    # quick shortcut for empty
    if not s:
        return {}
    # Try direct load first
    try:
        return json.loads(s)
    except Exception:
        pass
    # Common fixes:
    # 1) Trim surrounding backticks or stray surrounding quotes
    s_clean = s.strip()
    # remove wrapping backticks
    if s_clean.startswith('`') and s_clean.endswith('`'):
        s_clean = s_clean[1:-1].strip()
    # remove a single extra trailing quote if present
    if s_clean.count('"') % 2 == 1 and s_clean.endswith('"'):
        s_clean = s_clean[:-1]
    # Replace single quotes with double quotes when it's safe
    if "'" in s_clean and '"' not in s_clean:
        s_try = s_clean.replace("'", '"')
        try:
            return json.loads(s_try)
        except Exception:
            pass
    # Remove trailing commas before array/object close
    s_try = re.sub(r",\s*(\]|})", r"\1", s_clean)
    # Try to json.loads again
    try:
        return json.loads(s_try)
    except Exception:
        pass
    # As a last resort, try to extract a JSON object substring
    m = re.search(r"({[\s\S]*})", s_clean)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Could not parse safely
    raise ValueError(f"Unable to parse tool arguments as JSON: {s!r}")


def get_location_from_desc(desc):
    # match {"ln": 790, "cl": 7, "fl": "tif_dirwrite.c"}
    match = re.search(r"\{ \"ln\": (\d+), \"cl\": (\d+), \"fl\": \"(.+)\" \}", desc)
    if match:
        return f"{match.group(3)}:{match.group(1)}"
    # cl可能不存在
    match = re.search(r"\{ \"ln\": (\d+), \"fl\": \"(.+)\" \}", desc)
    if match:
        return f"{match.group(2)}:{match.group(1)}"
    return None

# {"group_id":1,"key_svfg_sequence":[],"key_svfg_sequence_desc":[]}
def read_group(group_json):
    key_svfg_sequence_desc = group_json["key_svfg_sequence_desc"]
    res_list = []
    for key_svfg_desc_item in key_svfg_sequence_desc:
        # LoadVFGNode ID: 40442 LoadStmt: [Var53353 <-- Var51621]\t\nValVar ID: 53353\n   %1466 = load i32, ptr %7, align 4, !dbg !13299 { \"ln\": 790, \"cl\": 7, \"fl\": \"tif_dirwrite.c\" }
        vfg_node_kind = key_svfg_desc_item.split(" ")[0]
        location = get_location_from_desc(key_svfg_desc_item)
        if location:
            res_list.append({"vfg_node_kind": vfg_node_kind, "location": location})
        else:
            res_list.append({"vfg_node_kind": vfg_node_kind, "location": None})        
    return res_list
   
def get_function_name(code_line):
    # 找到某个代码行中所有可能为函数调用的字段
    # 返回所有可能的函数名称列表
    code_line = code_line.strip()
    
    # C语言关键字列表，这些不是函数
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
    # 查找所有函数调用 pattern: function_name(args)
    # 使用正则表达式找到函数调用
    func_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    
    matches = list(re.finditer(func_pattern, code_line))
    
    function_names = []
    for match in matches:
        func_name = match.group(1)
        
        # 跳过C语言关键字
        if func_name in c_keywords:
            continue
        
        # 添加到函数名称列表（去重）
        if func_name not in function_names:
            function_names.append(func_name)
    
    return function_names

def get_arg_index(code_line, variable_name): 
    """
    找到变量在函数调用中的参数位置。
    
    Args:
        code_line: 代码行字符串
        variable_name: 要查找的变量名
        
    Returns:
        tuple: (function_name, arg_index) 如果找到，其中arg_index是0-based索引
               (None, None) 如果未找到
    """
    code_line = code_line.strip()
    
    # C语言关键字列表，这些不是函数
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
    # 查找所有函数调用 pattern: function_name(args)
    # 使用正则表达式找到函数调用
    func_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    
    matches = list(re.finditer(func_pattern, code_line))
    
    normalized_variable = variable_name.lstrip('&*')
    if not normalized_variable:
        normalized_variable = variable_name
    
    loose_pattern = re.compile(
        r'(?<![A-Za-z0-9_])(?:[&*])*' + re.escape(normalized_variable) + r'(?![A-Za-z0-9_])'
    )
    
    for match in matches:
        func_name = match.group(1)
        
        # 跳过C语言关键字
        if func_name in c_keywords:
            continue
            
        start_paren = match.end() - 1  # '(' 的位置
        
        # 找到匹配的右括号
        paren_count = 1
        i = start_paren + 1
        end_paren = -1
        
        while i < len(code_line) and paren_count > 0:
            if code_line[i] == '(':
                paren_count += 1
            elif code_line[i] == ')':
                paren_count -= 1
                if paren_count == 0:
                    end_paren = i
                    break
            i += 1
        
        if end_paren == -1:
            continue
        
        # 提取参数部分
        args_str = code_line[start_paren + 1:end_paren].strip()
        
        if not args_str:
            continue
        
        # 解析参数列表（考虑嵌套的括号和逗号）
        args = []
        current_arg = []
        depth = 0
        
        for char in args_str:
            if char == ',' and depth == 0:
                args.append(''.join(current_arg).strip())
                current_arg = []
            else:
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                current_arg.append(char)
        
        # 添加最后一个参数
        if current_arg:
            args.append(''.join(current_arg).strip())
        
        # 检查变量名是否在参数中
        for idx, arg in enumerate(args):
            # 检查变量名是否在参数中（可能是 &var, *var, var, var[i] 等形式）
            # 使用单词边界匹配，确保是完整的变量名
            if re.search(r'\b' + re.escape(variable_name) + r'\b', arg):
                return (func_name, idx)
            
            if loose_pattern.search(arg):
                return (func_name, idx)
    
    return (None, None)

def get_formal_arg_names(code_line):
    # 给定一个函数的声明或定义行 包含函数名称 找到所有形参的参数名称
    # TIFFSetField(TIFF* tif, uint32 tag, ...)
    """
    从C/C++函数声明或定义中提取形参名称
    
    Args:
        code_line: 函数声明或定义的代码行
        例如: "int foo(int x, char *y, size_t z)"
        
    Returns:
        dict:
            'args': 形参名称列表，例如 ['x', 'y', 'z']
            'has_varargs': 是否存在可变参数（...）
        如果解析失败返回 {'args': [], 'has_varargs': False}
    """
    # 查找第一个左括号
    has_varargs = False
    start_paren = code_line.find('(')
    if start_paren == -1:
        return {'args': [], 'has_varargs': False}
    
    # 查找匹配的右括号
    depth = 0
    end_paren = -1
    for i in range(start_paren, len(code_line)):
        if code_line[i] == '(':
            depth += 1
        elif code_line[i] == ')':
            depth -= 1
            if depth == 0:
                end_paren = i
                break
    
    if end_paren == -1:
        return {'args': [], 'has_varargs': False}
    
    # 提取参数部分
    args_str = code_line[start_paren + 1:end_paren].strip()
    
    if not args_str or args_str == 'void':
        return {'args': [], 'has_varargs': False}
    
    # 解析参数列表（考虑嵌套的括号和逗号）
    params = []
    current_param = []
    depth = 0
    
    for char in args_str:
        if char == ',' and depth == 0:
            params.append(''.join(current_param).strip())
            current_param = []
        else:
            if char == '(' or char == '[':
                depth += 1
            elif char == ')' or char == ']':
                depth -= 1
            current_param.append(char)
    
    # 添加最后一个参数
    if current_param:
        param_str = ''.join(current_param).strip()
        if param_str:
            params.append(param_str)
    
    # 从每个参数中提取变量名
    arg_names = []
    for param in params:
        # 跳过可变参数
        if param.strip() == '...':
            has_varargs = True
            continue
            
        # 移除默认值 (例如: int x = 5 -> int x)
        if '=' in param:
            param = param.split('=')[0].strip()
        
        # 处理函数指针: int (*callback)(void) -> callback
        # 查找 (*name) 模式
        func_ptr_match = re.search(r'\(\s*\*\s*(\w+)\s*\)', param)
        if func_ptr_match:
            arg_names.append(func_ptr_match.group(1))
            continue
        
        # 移除数组括号后的内容 (例如: char name[10] -> char name)
        param = re.sub(r'\[.*?\]', '', param)
        
        # 移除多余的空格和符号，准备提取变量名
        # 去掉指针/引用符号周围的空格: char * name -> char *name
        param = param.strip()
        
        # 从右向左找到最后一个标识符
        # 处理各种情况: int x, char *y, const int &z, int **p 等
        # 使用正则表达式找到最后一个合法的C标识符
        
        # 移除尾部的指针/引用符号和空格
        param = param.rstrip('*& \t')
        
        # 找到最后一个单词（变量名）
        tokens = re.findall(r'\w+', param)
        if tokens:
            # 最后一个token就是变量名
            arg_names.append(tokens[-1])
    
    return {'args': arg_names, 'has_varargs': has_varargs}

def get_actual_arg_names(code_line, func_name=None, return_call_index=False):
    """
    从C/C++函数调用中提取实参表达式列表
    
    Args:
        code_line: 包含函数调用的代码行
        func_name: 目标函数名（可选）。提供时将优先匹配该函数的调用。
        return_call_index: 是否返回函数名在当前行中的起始下标
        
    Returns:
        - return_call_index=False（默认）: 实参表达式列表，例如 ['a', 'b->field', 'arr[i]']
        - return_call_index=True: (实参表达式列表, 函数名起始下标)。如果未找到，起始下标为 -1
        如果解析失败返回空列表；结合 return_call_index=True 时返回 ([], -1)
    """
    if not code_line:
        return ([], -1) if return_call_index else []

    func_start_index = -1
    start_paren = -1

    if func_name:
        pattern = re.compile(r'(?<![A-Za-z0-9_])(' + re.escape(func_name) + r')\s*\(')
        match = pattern.search(code_line)
        if match:
            func_start_index = match.start(1)
            start_paren = code_line.find('(', match.end(1) - 1)
    else:
        call_pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')
        keywords = {
            'if', 'while', 'for', 'switch', 'return', 'sizeof', 'catch', 'new', 'delete',
            'else', 'case'
        }
        for match in call_pattern.finditer(code_line):
            candidate = match.group(1)
            if candidate in keywords:
                continue
            func_start_index = match.start(1)
            start_paren = code_line.find('(', match.end(1) - 1)
            break

    if start_paren == -1:
        # 回退到原始逻辑查找第一个左括号
        start_paren = code_line.find('(')

    if start_paren == -1:
        return ([], func_start_index) if return_call_index else []

    # 查找匹配的右括号（处理嵌套括号）
    depth = 0
    end_paren = -1
    for i in range(start_paren, len(code_line)):
        if code_line[i] == '(':
            depth += 1
        elif code_line[i] == ')':
            depth -= 1
            if depth == 0:
                end_paren = i
                break

    if end_paren == -1:
        return ([], func_start_index) if return_call_index else []

    # 提取参数部分
    args_str = code_line[start_paren + 1:end_paren].strip()

    if not args_str:
        return ([], func_start_index) if return_call_index else []

    # 解析参数列表（考虑嵌套的括号、方括号和逗号）
    actual_args = []
    current_arg = []
    depth = 0  # 括号和方括号的嵌套深度
    in_string = False  # 是否在字符串字面量中
    in_char = False    # 是否在字符字面量中
    escape = False     # 是否是转义字符

    for char in args_str:
        # 处理转义字符
        if escape:
            current_arg.append(char)
            escape = False
            continue

        if char == '\\':
            escape = True
            current_arg.append(char)
            continue

        if char == '"' and not in_char:
            in_string = not in_string
            current_arg.append(char)
            continue

        if char == "'" and not in_string:
            in_char = not in_char
            current_arg.append(char)
            continue

        # 如果在字符串或字符字面量中，直接添加
        if in_string or in_char:
            current_arg.append(char)
            continue

        # 处理括号和方括号的嵌套
        if char in '([{':
            depth += 1
            current_arg.append(char)
        elif char in ')]}':
            depth -= 1
            current_arg.append(char)
        elif char == ',' and depth == 0:
            # 遇到顶层逗号，分割参数
            arg_text = ''.join(current_arg).strip()
            if arg_text:
                actual_args.append(arg_text)
            current_arg = []
        else:
            current_arg.append(char)

    # 添加最后一个参数
    if current_arg:
        arg_text = ''.join(current_arg).strip()
        if arg_text:
            actual_args.append(arg_text)

    if return_call_index:
        return actual_args, func_start_index
    return actual_args

if __name__ == "__main__":
    json_str = '''[[{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2327', 'classification': 'NullPointer', 'source_location': None, 'reason': "_TIFFmalloc fails and returns NULL, so 'data' is a null pointer at the return point."}]]'''
    
    json_data = json.loads(json_str)
    print(json_data, indent=4)
    
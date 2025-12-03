import os
import subprocess
import shutil
from config import *
import logging
import datetime
import json
import re

# Tree-sitter imports
try:
    import tree_sitter
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

# Initialize tree-sitter parser for C
_c_parser = None
_c_language = None

def _load_language_from_capsule(capsule):
    """Wrap a PyCapsule returned by tree_sitter_* packages into a Language object."""
    lang = Language.__new__(Language)
    Language.__init__(lang, capsule)
    return lang

def _init_tree_sitter():
    """Initialize tree-sitter parser for C language."""
    global _c_parser, _c_language
    if not TREE_SITTER_AVAILABLE:
        return False
    if _c_parser is not None:
        return True

    errors = []
    candidate_language = None

    # Preferred path: use tree_sitter_languages (ships compiled grammars)
    try:
        from tree_sitter_languages import get_language
        lang = get_language("c")
        if isinstance(lang, Language):
            candidate_language = lang
        else:
            errors.append(f"tree_sitter_languages returned unexpected type {type(lang)}")
    except ImportError:
        errors.append("tree_sitter_languages not installed")
    except Exception as exc:
        errors.append(f"tree_sitter_languages failed: {exc}")

    # Fallback: legacy tree_sitter_c PyCapsule bindings
    if candidate_language is None:
        try:
            from tree_sitter_c import language as legacy_language
            capsule = legacy_language()
            if isinstance(capsule, Language):
                candidate_language = capsule
            else:
                try:
                    candidate_language = _load_language_from_capsule(capsule)
                except Exception as wrap_exc:
                    errors.append(f"tree_sitter_c returned unsupported object {type(capsule)}: {wrap_exc}")
        except ImportError:
            errors.append("tree_sitter_c not installed")
        except Exception as exc:
            errors.append(f"tree_sitter_c failed: {exc}")

    if candidate_language is None:
        logging.warning("Failed to initialize tree-sitter C language. Attempts: %s", "; ".join(errors))
        return False

    _c_language = candidate_language

    try:
        parser = Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(_c_language)
        else:
            parser.language = _c_language
        _c_parser = parser
        return True
    except TypeError:
        # Extremely old bindings may still expect Parser(language)
        try:
            _c_parser = Parser(_c_language)
            return True
        except Exception as exc:
            logging.warning(f"Failed to bind parser to tree-sitter language: {exc}")
    except Exception as exc:
        logging.warning(f"Failed to initialize tree-sitter parser: {exc}")

    return False

def parse_code_line(code_line):
    """
    解析单行C代码并返回AST根节点。
    
    Args:
        code_line: C代码行字符串
        
    Returns:
        tree_sitter.Node: AST根节点，如果解析失败返回None
    """
    if not _init_tree_sitter():
        return None
    if not code_line or not code_line.strip():
        return None
    
    # 确保代码行以分号结尾（如果还没有）
    code = code_line.strip()
    if not code.endswith(';') and not code.endswith('}') and not code.endswith('{'):
        # 检查是否已经是完整语句
        if not any(code.endswith(c) for c in [';', '}', '{', ')']):
            code = code + ';'
    
    try:
        tree = _c_parser.parse(bytes(code, 'utf8'))
        return tree.root_node
    except Exception as e:
        logging.debug(f"Failed to parse code line '{code_line}': {e}")
        return None

def _extract_identifier_from_node(node, code_bytes):
    """
    从AST节点中提取标识符名称。
    处理各种情况：直接标识符、指针解引用、数组访问、结构体成员访问等。
    
    Args:
        node: tree-sitter节点
        code_bytes: 原始代码的字节串
        
    Returns:
        str: 标识符名称，如果无法提取返回None
    """
    if node is None:
        return None
    
    # 如果是标识符节点，直接返回
    if node.type == 'identifier':
        return code_bytes[node.start_byte:node.end_byte].decode('utf8')
    
    # 处理指针解引用 *ptr
    if node.type == 'pointer_expression':
        operand = node.child_by_field_name('operand')
        if operand:
            return _extract_identifier_from_node(operand, code_bytes)
    
    # 处理数组访问 arr[index]
    if node.type == 'subscript_expression':
        array = node.child_by_field_name('argument')
        if array:
            return _extract_identifier_from_node(array, code_bytes)
    
    # 处理结构体成员访问 obj.field 或 obj->field
    if node.type == 'field_expression':
        field = node.child_by_field_name('field')
        if field:
            return _extract_identifier_from_node(field, code_bytes)
    
    # 处理括号表达式 (expr)
    if node.type == 'parenthesized_expression':
        expression = node.child_by_field_name('expression')
        if expression:
            return _extract_identifier_from_node(expression, code_bytes)
    
    # 对于其他类型，尝试查找第一个标识符子节点
    for child in node.children:
        if child.type == 'identifier':
            return code_bytes[child.start_byte:child.end_byte].decode('utf8')
        result = _extract_identifier_from_node(child, code_bytes)
        if result:
            return result
    
    return None

# 设置日志
def setup_logger(log_type):
    main_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    llm_formatter = logging.Formatter("%(message)s")
    time_str = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    if log_type == "main":
        sar = SAR_ROOT_PATH if sar_name is None else sar_name.split('.')[0]
        log_file_name = f"{sar}-{time_str}.log"
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
        log_file_name = f"result_{sar_name.split('.')[0]}_{LLM_TYPE}-{ANALYZER_TYPE}-{time_str}.log"
        if not os.path.exists(os.path.join(RES_ROOT_PATH, "RESULT")):
            os.makedirs(os.path.join(RES_ROOT_PATH, "RESULT"))
        log_file_path = os.path.join(RES_ROOT_PATH, "RESULT", log_file_name)
        logger = logging.getLogger(f"result_{sar_name.split('.')[0]}_{LLM_TYPE}")
        logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(log_file_path, mode="a")
        file_handler.setFormatter(llm_formatter)
        logger.addHandler(file_handler)
        return logger
    elif log_type == "analysis":
        log_file_name = f"analysis_{sar_name.split('.')[0]}_{LLM_TYPE}-{ANALYZER_TYPE}-{time_str}.log"
        if not os.path.exists(os.path.join(RES_ROOT_PATH, "TRACE")):
            os.makedirs(os.path.join(RES_ROOT_PATH, "TRACE"))
        log_file_path = os.path.join(RES_ROOT_PATH, "TRACE", log_file_name)
        logger = logging.getLogger(f"analysis_{sar_name.split('.')[0]}_{LLM_TYPE}")
        logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(log_file_path, mode="a")
        file_handler.setFormatter(llm_formatter)
        logger.addHandler(file_handler)
        return logger
    else:
        raise ValueError("Invalid log type")

# 找到指定项目中指定文件名的路径
# def find_file_path(file_name):
#     for root, dirs, files in os.walk(os.path.join(PUT_ROOT_PATH, PROJECT_NAME)):
#         if file_name in files:
#             # 路径中不包含PUT_ROOT_PATH
#             full_path = os.path.join(root, file_name)
#             return os.path.relpath(full_path, PUT_ROOT_PATH)
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
    
    # 移除 PROJECT_NAME 前缀（如果存在）
    if input_dir.startswith(PROJECT_NAME + '/'):
        input_dir = input_dir[len(PROJECT_NAME) + 1:]
    
    # 搜索所有匹配的文件路径
    matching_paths = []
    for root, dirs, files in os.walk(os.path.join(PUT_ROOT_PATH, PROJECT_NAME)):
        if base_name in files:
            full_path = os.path.join(root, base_name)
            rel_path = os.path.relpath(full_path, PUT_ROOT_PATH)
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
        for path in matching_paths:
            # 标准化路径用于比较
            normalized_path = path.replace('\\', '/').replace(os.sep, '/')
            
            # 必须路径结尾能够匹配
            if not normalized_path.endswith(input_dir + '/' + base_name):
                # 在当前path list中删除这个path
                matching_paths.remove(path)
                continue
    
    return min(matching_paths, key=len)

# 根据指定scource_location找到对应的代码行
def find_code_line(source_location, strip_whitespace=True):
    file_name = source_location.split(":")[0]
    file_path = find_file_path(file_name)
    file_path = os.path.join(PUT_ROOT_PATH, file_path)
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
    从赋值表达式中提取左值变量名（使用tree-sitter）。
    
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
    assignment = assignment.strip()
    
    # 检查是否是return语句（不是赋值）
    if assignment.startswith('return '):
        return None
    
    # 尝试使用tree-sitter解析
    root = parse_code_line(assignment)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _extract_lhs_variable_fallback(assignment)
    
    code_bytes = bytes(assignment, 'utf8')
    
    # 查找赋值表达式节点
    def find_assignment(node):
        """递归查找赋值表达式节点"""
        if node.type == 'assignment_expression':
            return node
        for child in node.children:
            result = find_assignment(child)
            if result:
                return result
        return None
    
    assign_node = find_assignment(root)
    if assign_node is None:
        return None
    
    # 获取左值节点
    left_node = assign_node.child_by_field_name('left')
    if left_node is None:
        return None
    
    # 提取标识符
    var_name = _extract_identifier_from_node(left_node, code_bytes)
    return var_name

def _extract_lhs_variable_fallback(assignment):
    """回退实现：使用原始的正则表达式方法"""
    assignment = assignment.strip()
    
    # 查找赋值运算符（排除 ==, !=, <=, >= 等比较运算符）
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
            next_char = assignment[i + 1] if i + 1 < len(assignment) else ''
            prev_char = assignment[i - 1] if i > 0 else ''
            
            if next_char not in ['='] and prev_char not in ['!', '<', '>', '=', '+', '-', '*', '/', '%', '&', '|', '^']:
                assign_candidates.append((i, paren_depth))
            i += 1
        else:
            i += 1
    
    if not assign_candidates:
        return None
    
    depth_zero = [pos for pos, depth in assign_candidates if depth == 0]
    if depth_zero:
        assign_pos = depth_zero[0]
    else:
        max_depth = max(depth for _, depth in assign_candidates)
        assign_pos = next(pos for pos, depth in assign_candidates if depth == max_depth)
    
    lhs = assignment[:assign_pos].strip()
    
    while True:
        lhs = lhs.strip()
        changed = False
        
        for keyword in ['if', 'while', 'for', 'switch']:
            if lhs.startswith(keyword + ' '):
                lhs = lhs[len(keyword):].strip()
                changed = True
                break
            if lhs.startswith(keyword + '('):
                lhs = lhs[len(keyword):].strip()
                changed = True
                break
        
        if lhs.startswith('('):
            lhs = lhs[1:].strip()
            changed = True
        
        if not changed:
            break
    
    lhs = lhs.strip()
    parts = lhs.split()
    if len(parts) > 1:
        lhs = parts[-1]
    
    lhs = lhs.lstrip('*')
    if '[' in lhs:
        lhs = lhs[:lhs.index('[')]
    if '->' in lhs:
        lhs = lhs.split('->')[-1]
    if '.' in lhs:
        lhs = lhs.split('.')[-1]
    
    lhs = lhs.strip()
    if lhs and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', lhs):
        return lhs
    
    return None

# 获取赋值等号在代码行中的位置
def get_eq_position(assignment, preserve_whitespace=True):
    """
    找到赋值表达式中等号的字符位置（使用tree-sitter）。
    
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
    
    # 尝试使用tree-sitter解析
    root = parse_code_line(assignment)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _get_eq_position_fallback(assignment, preserve_whitespace, original_assignment)
    
    code_bytes = bytes(assignment, 'utf8')
    
    # 查找赋值表达式节点
    def find_assignment(node):
        """递归查找赋值表达式节点"""
        if node.type == 'assignment_expression':
            return node
        for child in node.children:
            result = find_assignment(child)
            if result:
                return result
        return None
    
    assign_node = find_assignment(root)
    if assign_node is None:
        return None
    
    # 查找赋值运算符'='的位置
    # 在assignment_expression中，运算符在left和right之间
    # tree-sitter的assignment_expression结构: left operator right
    # 查找'='字符的位置
    left_node = assign_node.child_by_field_name('left')
    right_node = assign_node.child_by_field_name('right')
    
    if left_node and right_node:
        # '='在left和right之间
        eq_position = left_node.end_byte
        # 跳过空白字符，找到'='
        while eq_position < right_node.start_byte:
            char = code_bytes[eq_position:eq_position+1].decode('utf8')
            if char == '=':
                # 如果preserve_whitespace为False，需要调整位置
                if not preserve_whitespace and assignment != original_assignment:
                    # 计算前导空白字符数
                    leading_whitespace = len(original_assignment) - len(original_assignment.lstrip())
                    eq_position = eq_position - leading_whitespace
                return eq_position
            eq_position += 1
    
    # 如果没有找到，尝试在节点文本中查找'='
    assign_text = code_bytes[assign_node.start_byte:assign_node.end_byte].decode('utf8')
    eq_pos_in_text = assign_text.find('=')
    if eq_pos_in_text != -1:
        eq_position = assign_node.start_byte + eq_pos_in_text
        # 如果preserve_whitespace为False，需要调整位置
        if not preserve_whitespace and assignment != original_assignment:
            leading_whitespace = len(original_assignment) - len(original_assignment.lstrip())
            eq_position = eq_position - leading_whitespace
        return eq_position
    
    return None

def _get_eq_position_fallback(assignment, preserve_whitespace, original_assignment):
    """回退实现：使用原始的正则表达式方法"""
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
            next_char = assignment[i + 1] if i + 1 < len(assignment) else ''
            prev_char = assignment[i - 1] if i > 0 else ''
            
            if next_char not in ['='] and prev_char not in ['!', '<', '>', '=', '+', '-', '*', '/', '%', '&', '|', '^']:
                assign_candidates.append((i, paren_depth))
            i += 1
        else:
            i += 1
    
    if not assign_candidates:
        return None
    
    depth_zero = [pos for pos, depth in assign_candidates if depth == 0]
    if depth_zero:
        assign_pos = depth_zero[0]
    else:
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
    """
    找到某个代码行中所有可能为函数调用的字段（使用tree-sitter）。
    返回所有可能的函数名称列表。
    """
    code_line = code_line.strip()
    
    # 尝试使用tree-sitter解析
    root = parse_code_line(code_line)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _get_function_name_fallback(code_line)
    
    code_bytes = bytes(code_line, 'utf8')
    function_names = []
    
    # C语言关键字列表，这些不是函数
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
    # 查找所有call_expression节点
    def find_call_expressions(node):
        """递归查找所有函数调用表达式"""
        calls = []
        if node.type == 'call_expression':
            calls.append(node)
        for child in node.children:
            calls.extend(find_call_expressions(child))
        return calls
    
    call_nodes = find_call_expressions(root)
    
    for call_node in call_nodes:
        # 获取函数名节点
        function_node = call_node.child_by_field_name('function')
        if function_node is None:
            continue
        
        # 提取函数名
        if function_node.type == 'identifier':
            func_name = code_bytes[function_node.start_byte:function_node.end_byte].decode('utf8')
        else:
            # 可能是更复杂的表达式，尝试提取标识符
            func_name = _extract_identifier_from_node(function_node, code_bytes)
        
        if func_name and func_name not in c_keywords and func_name not in function_names:
            function_names.append(func_name)
    
    return function_names

def _get_function_name_fallback(code_line):
    """回退实现：使用原始的正则表达式方法"""
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
    func_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    matches = list(re.finditer(func_pattern, code_line))
    
    function_names = []
    for match in matches:
        func_name = match.group(1)
        if func_name in c_keywords:
            continue
        if func_name not in function_names:
            function_names.append(func_name)
    
    return function_names

def get_arg_index(code_line, variable_name): 
    """
    找到变量在函数调用中的参数位置（使用tree-sitter）。
    
    Args:
        code_line: 代码行字符串
        variable_name: 要查找的变量名
        
    Returns:
        tuple: (function_name, arg_index) 如果找到，其中arg_index是0-based索引
               (None, None) 如果未找到
    """
    code_line = code_line.strip()
    
    # 尝试使用tree-sitter解析
    root = parse_code_line(code_line)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _get_arg_index_fallback(code_line, variable_name)
    
    code_bytes = bytes(code_line, 'utf8')
    
    # C语言关键字列表
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
    normalized_variable = variable_name.lstrip('&*')
    if not normalized_variable:
        normalized_variable = variable_name
    
    # 查找所有call_expression节点
    def find_call_expressions(node):
        """递归查找所有函数调用表达式"""
        calls = []
        if node.type == 'call_expression':
            calls.append(node)
        for child in node.children:
            calls.extend(find_call_expressions(child))
        return calls
    
    call_nodes = find_call_expressions(root)
    
    for call_node in call_nodes:
        # 获取函数名
        function_node = call_node.child_by_field_name('function')
        if function_node is None:
            continue
        
        if function_node.type == 'identifier':
            func_name = code_bytes[function_node.start_byte:function_node.end_byte].decode('utf8')
        else:
            func_name = _extract_identifier_from_node(function_node, code_bytes)
        
        if not func_name or func_name in c_keywords:
            continue
        
        # 获取参数列表
        arguments_node = call_node.child_by_field_name('arguments')
        if arguments_node is None:
            continue
        
        # 遍历参数
        arg_index = 0
        for child in arguments_node.children:
            if child.type == 'argument_list':
                # 参数列表节点，遍历其子节点
                for arg_child in child.children:
                    if arg_child.type == ',':
                        continue  # 跳过逗号
                    # 检查参数中是否包含目标变量
                    arg_text = code_bytes[arg_child.start_byte:arg_child.end_byte].decode('utf8')
                    if _variable_in_expression(arg_child, code_bytes, variable_name, normalized_variable):
                        return (func_name, arg_index)
                    arg_index += 1
            elif child.type != ',':
                # 直接是参数节点
                if _variable_in_expression(child, code_bytes, variable_name, normalized_variable):
                    return (func_name, arg_index)
                arg_index += 1
    
    return (None, None)

def _variable_in_expression(node, code_bytes, variable_name, normalized_variable):
    """检查表达式中是否包含目标变量"""
    if node is None:
        return False
    
    # 如果是标识符节点，直接比较
    if node.type == 'identifier':
        ident = code_bytes[node.start_byte:node.end_byte].decode('utf8')
        return ident == variable_name or ident == normalized_variable
    
    # 递归检查子节点
    for child in node.children:
        if _variable_in_expression(child, code_bytes, variable_name, normalized_variable):
            return True
    
    # 检查节点文本中是否包含变量名
    node_text = code_bytes[node.start_byte:node.end_byte].decode('utf8')
    if re.search(r'\b' + re.escape(variable_name) + r'\b', node_text):
        return True
    if re.search(r'\b' + re.escape(normalized_variable) + r'\b', node_text):
        return True
    
    return False

def _get_arg_index_fallback(code_line, variable_name):
    """回退实现：使用原始的正则表达式方法"""
    c_keywords = {
        'if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue',
        'goto', 'case', 'default', 'sizeof', 'typeof', '__typeof__', 
        'static', 'extern', 'auto', 'register', 'volatile', 'const',
        'struct', 'union', 'enum', 'typedef'
    }
    
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
        if func_name in c_keywords:
            continue
            
        start_paren = match.end() - 1
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
        
        args_str = code_line[start_paren + 1:end_paren].strip()
        if not args_str:
            continue
        
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
        
        if current_arg:
            args.append(''.join(current_arg).strip())
        
        for idx, arg in enumerate(args):
            if re.search(r'\b' + re.escape(variable_name) + r'\b', arg):
                return (func_name, idx)
            if loose_pattern.search(arg):
                return (func_name, idx)
    
    return (None, None)

def get_formal_arg_names(code_line):
    """
    从C/C++函数声明或定义中提取形参名称（使用tree-sitter）。
    
    Args:
        code_line: 函数声明或定义的代码行
        例如: "int foo(int x, char *y, size_t z)"
        
    Returns:
        dict:
            'args': 形参名称列表，例如 ['x', 'y', 'z']
            'has_varargs': 是否存在可变参数（...）
        如果解析失败返回 {'args': [], 'has_varargs': False}
    """
    code_line = code_line.strip()
    
    # 尝试使用tree-sitter解析
    root = parse_code_line(code_line)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _get_formal_arg_names_fallback(code_line)
    
    code_bytes = bytes(code_line, 'utf8')
    arg_names = []
    has_varargs = False
    
    # 查找function_definition或declaration节点
    def find_function_declaration(node):
        """查找函数定义或声明节点"""
        if node.type in ['function_definition', 'declaration']:
            return node
        for child in node.children:
            result = find_function_declaration(child)
            if result:
                return result
        return None
    
    func_node = find_function_declaration(root)
    if func_node is None:
        return {'args': [], 'has_varargs': False}
    
    # 获取参数列表
    # 对于function_definition，参数在declarator中
    # 对于declaration，参数也在declarator中
    declarator = func_node.child_by_field_name('declarator')
    if declarator is None:
        # 尝试直接查找parameter_list
        param_list = func_node.child_by_field_name('parameters')
        if param_list is None:
            return {'args': [], 'has_varargs': False}
    else:
        # 从declarator中查找parameter_list
        param_list = declarator.child_by_field_name('parameters')
        if param_list is None:
            return {'args': [], 'has_varargs': False}
    
    # 遍历参数列表
    for child in param_list.children:
        if child.type == 'parameter_declaration':
            # 提取参数名
            declarator_node = child.child_by_field_name('declarator')
            if declarator_node:
                # 从declarator中提取标识符
                param_name = _extract_identifier_from_declarator(declarator_node, code_bytes)
                if param_name:
                    arg_names.append(param_name)
            else:
                # 可能没有declarator，尝试从整个参数声明中提取
                param_name = _extract_identifier_from_node(child, code_bytes)
                if param_name:
                    arg_names.append(param_name)
        elif child.type == 'variadic_parameter' or (child.type == '...'):
            has_varargs = True
        elif child.type == 'identifier':
            # 直接是标识符参数
            param_name = code_bytes[child.start_byte:child.end_byte].decode('utf8')
            if param_name:
                arg_names.append(param_name)
    
    return {'args': arg_names, 'has_varargs': has_varargs}

def _extract_identifier_from_declarator(declarator_node, code_bytes):
    """从declarator节点中提取标识符名称"""
    if declarator_node is None:
        return None
    
    # 查找identifier子节点
    if declarator_node.type == 'identifier':
        return code_bytes[declarator_node.start_byte:declarator_node.end_byte].decode('utf8')
    
    # 对于pointer_declarator，查找declarator字段
    if declarator_node.type == 'pointer_declarator':
        inner_declarator = declarator_node.child_by_field_name('declarator')
        if inner_declarator:
            return _extract_identifier_from_declarator(inner_declarator, code_bytes)
    
    # 对于function_declarator，查找declarator字段
    if declarator_node.type == 'function_declarator':
        inner_declarator = declarator_node.child_by_field_name('declarator')
        if inner_declarator:
            return _extract_identifier_from_declarator(inner_declarator, code_bytes)
    
    # 对于array_declarator，查找declarator字段
    if declarator_node.type == 'array_declarator':
        inner_declarator = declarator_node.child_by_field_name('declarator')
        if inner_declarator:
            return _extract_identifier_from_declarator(inner_declarator, code_bytes)
    
    # 递归查找identifier子节点
    for child in declarator_node.children:
        if child.type == 'identifier':
            return code_bytes[child.start_byte:child.end_byte].decode('utf8')
        result = _extract_identifier_from_declarator(child, code_bytes)
        if result:
            return result
    
    return None

def _get_formal_arg_names_fallback(code_line):
    """回退实现：使用原始的正则表达式方法"""
    has_varargs = False
    start_paren = code_line.find('(')
    if start_paren == -1:
        return {'args': [], 'has_varargs': False}
    
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
    
    args_str = code_line[start_paren + 1:end_paren].strip()
    if not args_str or args_str == 'void':
        return {'args': [], 'has_varargs': False}
    
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
    
    if current_param:
        param_str = ''.join(current_param).strip()
        if param_str:
            params.append(param_str)
    
    arg_names = []
    for param in params:
        if param.strip() == '...':
            has_varargs = True
            continue
        
        if '=' in param:
            param = param.split('=')[0].strip()
        
        func_ptr_match = re.search(r'\(\s*\*\s*(\w+)\s*\)', param)
        if func_ptr_match:
            arg_names.append(func_ptr_match.group(1))
            continue
        
        param = re.sub(r'\[.*?\]', '', param)
        param = param.strip()
        param = param.rstrip('*& \t')
        
        tokens = re.findall(r'\w+', param)
        if tokens:
            arg_names.append(tokens[-1])
    
    return {'args': arg_names, 'has_varargs': has_varargs}

def get_actual_arg_names(code_line, func_name=None, return_call_index=False):
    """
    从C/C++函数调用中提取实参表达式列表（使用tree-sitter）。
    
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

    # 尝试使用tree-sitter解析
    root = parse_code_line(code_line)
    if root is None:
        # 如果tree-sitter解析失败，回退到原始实现
        return _get_actual_arg_names_fallback(code_line, func_name, return_call_index)
    
    code_bytes = bytes(code_line, 'utf8')
    
    # 查找call_expression节点
    def find_call_expressions(node):
        """递归查找所有函数调用表达式"""
        calls = []
        if node.type == 'call_expression':
            calls.append(node)
        for child in node.children:
            calls.extend(find_call_expressions(child))
        return calls
    
    call_nodes = find_call_expressions(root)
    
    # 如果指定了函数名，优先匹配
    target_call = None
    func_start_index = -1
    
    for call_node in call_nodes:
        function_node = call_node.child_by_field_name('function')
        if function_node is None:
            continue
        
        if function_node.type == 'identifier':
            current_func_name = code_bytes[function_node.start_byte:function_node.end_byte].decode('utf8')
        else:
            current_func_name = _extract_identifier_from_node(function_node, code_bytes)
        
        if func_name:
            if current_func_name == func_name:
                target_call = call_node
                func_start_index = function_node.start_byte
                break
        else:
            # 没有指定函数名，选择第一个非关键字的调用
            keywords = {
                'if', 'while', 'for', 'switch', 'return', 'sizeof', 'catch', 'new', 'delete',
                'else', 'case'
            }
            if current_func_name and current_func_name not in keywords:
                target_call = call_node
                func_start_index = function_node.start_byte
                break
    
    # 如果没有找到匹配的调用，使用第一个调用
    if target_call is None and call_nodes:
        target_call = call_nodes[0]
        function_node = target_call.child_by_field_name('function')
        if function_node:
            func_start_index = function_node.start_byte
    
    if target_call is None:
        return ([], func_start_index) if return_call_index else []
    
    # 提取参数列表
    arguments_node = target_call.child_by_field_name('arguments')
    if arguments_node is None:
        return ([], func_start_index) if return_call_index else []
    
    actual_args = []
    
    # 在tree-sitter中，arguments字段通常包含括号和参数
    # 我们需要找到参数列表部分（在括号内）
    # 遍历arguments节点的子节点，跳过'('和')'
    for child in arguments_node.children:
        if child.type == ',':
            continue  # 跳过逗号
        elif child.type in ['(', ')']:
            continue  # 跳过括号
        elif child.type == 'argument_list':
            # 如果存在argument_list节点，遍历其子节点
            for arg_child in child.children:
                if arg_child.type == ',':
                    continue
                arg_text = code_bytes[arg_child.start_byte:arg_child.end_byte].decode('utf8').strip()
                if arg_text:
                    actual_args.append(arg_text)
        else:
            # 直接是参数表达式节点
            arg_text = code_bytes[child.start_byte:child.end_byte].decode('utf8').strip()
            if arg_text and arg_text not in ['(', ')']:
                actual_args.append(arg_text)
    
    if return_call_index:
        return actual_args, func_start_index
    return actual_args

def _get_actual_arg_names_fallback(code_line, func_name, return_call_index):
    """回退实现：使用原始的正则表达式方法"""
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
        start_paren = code_line.find('(')

    if start_paren == -1:
        return ([], func_start_index) if return_call_index else []

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

    args_str = code_line[start_paren + 1:end_paren].strip()
    if not args_str:
        return ([], func_start_index) if return_call_index else []

    actual_args = []
    current_arg = []
    depth = 0
    in_string = False
    in_char = False
    escape = False

    for char in args_str:
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

        if in_string or in_char:
            current_arg.append(char)
            continue

        if char in '([{':
            depth += 1
            current_arg.append(char)
        elif char in ')]}':
            depth -= 1
            current_arg.append(char)
        elif char == ',' and depth == 0:
            arg_text = ''.join(current_arg).strip()
            if arg_text:
                actual_args.append(arg_text)
            current_arg = []
        else:
            current_arg.append(char)

    if current_arg:
        arg_text = ''.join(current_arg).strip()
        if arg_text:
            actual_args.append(arg_text)

    if return_call_index:
        return actual_args, func_start_index
    return actual_args


def generate_ctags_index(force=False):
    """
    Create (or refresh) a ctags index for all C/C++ sources in the PUT project.

    Args:
        force (bool): When True, rebuilds the tags file even if it already exists.

    Returns:
        dict: {'status': 'generated'|'skipped', 'path': <tags_path>} on success,
              or {'error': <message>} when the operation fails.
    """
    project_root = os.path.join(PUT_ROOT_PATH, PROJECT_NAME)
    tags_path = os.path.join(project_root, "tags")

    if not force and os.path.exists(tags_path):
        return {"status": "skipped", "path": tags_path}

    ctags_bin = shutil.which("ctags")
    if not ctags_bin:
        message = "ctags executable not found in PATH. Please install universal ctags."
        logging.warning(message)
        return {"error": message}

    if not os.path.isdir(project_root):
        message = f"Project root does not exist: {project_root}"
        logging.error(message)
        return {"error": message}

    cmd = [
        ctags_bin,
        "-R",
        "--fields=+n",
        "--languages=C,C++",
        "-f",
        "tags",
        ".",
    ]

    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        message = f"Failed to execute ctags: {exc}"
        logging.error(message)
        return {"error": message}

    if result.returncode != 0:
        message = (
            f"ctags command failed (exit {result.returncode}). "
            f"stdout: {result.stdout or '<empty>'} "
            f"stderr: {result.stderr or '<empty>'}"
        )
        logging.error(message)
        return {"error": message}

    logging.info(f"Generated ctags index at {tags_path}")
    return {"status": "generated", "path": tags_path}

if __name__ == "__main__":
    json_str = '''[[{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2525', 'classification': 'Transferred with assignment', 'source_location': 'tif_dirread.c:2524', 'reason': "Memory allocated to 'data' is assigned to '*value' output parameter at line 2524, transferring ownership to the caller.", 'arg': 'value'}], [{'var_info': {'var_name': 'data', 'var_type': 'local_var', 'arg_index': 6, 'gep_info': {'gep_type': 'not_struct', 'baseobj_name': None, 'member_name': None, 'offset': 0, 'baseobj_type': 'ptr'}}, 'start_location': 'tif_dirread.c:2323', 'function_name': 'TIFFReadDirEntryFloatArray', 'return_location': 'tif_dirread.c:2327', 'classification': 'NullPointer', 'source_location': None, 'reason': "_TIFFmalloc fails and returns NULL, so 'data' is a null pointer at the return point."}]]'''
    
    json_data = json.loads(json_str)
    print(json_data, indent=4)
    
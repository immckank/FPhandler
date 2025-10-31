import os
from config import *
import logging
import datetime
import json
import re

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
        logger.setLevel(logging.INFO)
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
        logger.setLevel(logging.INFO)
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
    if input_dir:
        best_match = None
        best_score = -1
        
        for path in matching_paths:
            # 标准化路径用于比较
            normalized_path = path.replace('\\', '/').replace(os.sep, '/')
            
            # 如果完全包含输入的相对路径，优先选择
            if input_dir in normalized_path:
                # 计算匹配度：路径结尾匹配越长，得分越高
                if normalized_path.endswith(input_dir + '/' + base_name):
                    return path  # 完美匹配，直接返回
                
                # 计算路径相似度
                score = len(input_dir)
                if score > best_score:
                    best_score = score
                    best_match = path
        
        if best_match:
            return best_match
    
    # 如果没有匹配成功或只传入文件名，返回第一个找到的
    return matching_paths[0]

# 根据指定scource_location找到对应的代码行
def find_code_line(source_location):
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
        return lines[line_number].strip()

# 提取赋值表达式的左值变量名
def extract_lhs_variable(assignment):
    assignment = assignment.strip()
    if '=' in assignment:
        lhs = assignment.split('=')[0].strip()
        # 变量名通常是LHS（左手边）的最后一个词
        parts = lhs.split()
        if not parts:
            return None
        # 移除所有前缀的星号和后缀的方括号
        variable_name = parts[-1].lstrip('*').rstrip('[]')
        return variable_name
    return None

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

if __name__ == "__main__":
    print(f"find tiffcrop.c : {find_file_path('tiffcrop.c')}")
    print(f"code line : {find_code_line('tiffcrop.c:175')}")
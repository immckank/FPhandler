import os
import subprocess
import logging
import sys

PUT_ROOT_PATH = "PUT"

'''
structure
'''

# dump_source_file
# Return a slice of a source  file with line numbers.
# return: string
def dump_source_file(source_location, start_line, end_line):
    file_path = os.path.join(PUT_ROOT_PATH, source_location.split(":")[0])
    with open(file_path, "r") as f:
        lines = f.readlines()
        return "".join(lines[start_line - 1:end_line])
    return None

# find_var_decl
# Find the source location of a  variable’s declaration.
# return: source_location: 'memcached/slab_automove.c:37'
def find_var_decl(source_location, var_name):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None

# find_callers
# Find all functions that  call a target function.
# return: list < function_name, source_location >
def find_callers(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return []

# find_callee
# Find the body of a function  called at a given location.
# return: function_name, source_location
def find_callee(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None

# ctags_readtags
# Find definition locations  for an identifier using ctags.
# return: list < source_location >
def ctags_readtags(source_location, id_name):
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

# find_var_definitions
# Find all definition sites  of a variable from a use site.
# return: list < source_location >
def find_var_definitions(source_location, var_name):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return []

'''
path condition
'''

# get_path_constraint
# Compute the path condition to  reach a given source line.
# return: exp
def get_path_constraint(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None

# check_always_implying、
# Check if one path constraint  logically implies another.
# exp1  exp2
# return: bool
def check_always_implying(exp1, exp2):
    # 基于求解器来实现
    return None

'''
bound
'''


# check_le
# Check if exp1 ≤ exp2  always holds.
# exp1  exp2
# return: bool
def check_le(exp1, exp2):
    # 基于求解器来实现
    return None

'''
context
'''

# dump_func_context
# 得到函数实现所在第一行 打印全部函数实现
# return: string
def dump_func_context(source_location):
    func_context = ""
    file_path = os.path.join(PUT_ROOT_PATH, source_location.split(":")[0])
    line_number = int(source_location.split(":")[1])
    with open(file_path, "r") as f:
        lines = f.readlines()
        # 找到函数实现的结束行
        start_line = line_number - 1
        brace_count = 0
        for i in range(line_number - 1, len(lines)):
            brace_count += lines[i].count("{")
            brace_count -= lines[i].count("}")
            if brace_count == 0:
                end_line = i
                break
        # 打印函数实现
        for i in range(start_line, end_line + 1):
            func_context += lines[i]
        return func_context
    return None

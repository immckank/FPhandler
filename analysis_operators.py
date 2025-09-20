import os
import subprocess
import logging
import sys



PUT_ROOT_PATH = "PUT"

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



# find_func_context
# 判断source location及变量是否在一个函数中
# 返回函数实现所在的source location
def find_func_context(source_location):
    file_path = os.path.join(PUT_ROOT_PATH, source_location.split(":")[0])
    line_number = int(source_location.split(":")[1])
    with open(file_path, "r") as f:
        lines = f.readlines()
        # TODO: 这里简单找括号 没有处理任何
        # TODO: 建议从LLVM中去实现
        for i in range(line_number - 1, -1, -1):
            if "{" in lines[i]:
                return f"{file_path.replace(PUT_ROOT_PATH, '').replace('\\', '/').lstrip('/')}:{i + 1}"
    return None

# dump_func_context
# 得到函数实现所在第一行 打印全部函数实现
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


print(find_var_decl("memcached/logger.c:756", "ret"))  # memcached/slab_automove.c:37
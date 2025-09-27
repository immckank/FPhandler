import os
import subprocess
import logging
import sys
import json
import re


from command_caller import CommandCaller

PUT_ROOT_PATH = "PUT"
PROJECT_NAME = "memcached"

'''
structure function
'''

# find_callers
# 找到所有调用目标函数的其他函数
# return: list < source_location >
# D
def find_callers(function_name):
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader("find-call-sites", function_name, os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc"))
    caller_source_location_list = []
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            # TODO 说明错误
            print(error)
        else:
            # 删除error属性
            del res_json["error"]
            # {'call_sites': [{'location': 'proto_text.c:581'}, {'location': 'proto_bin.c:602'}]}
            # 为每个call_site添加code属性
            for call_site in res_json.get("call_sites", []):
                call_site["code"] = dump_source_line(call_site["location"].split(":")[0], call_site["location"].split(":")[1])
                caller_source_location_list.append(call_site["location"])
            return res_json
    return []

# find_callee
# 找到被调用函数的函数体
# return: 
# D
def find_callee(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.c:\d+$', source_location) and not re.match(r'^[\w/]+\.h:\d+$', source_location):
        print(f"Invalid source location format: {source_location}")
        return None
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader("find-callee-body", source_location, os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc"))
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            # TODO 说明错误
            print(error)
        else:
            # 删除error属性
            del res_json["error"]
            callee_functions = res_json.get("callee_functions", [])
            for func in callee_functions:
                func_body = dump_source_file(func["filename"], func['start_line'], func['end_line'])
                # 为func添加func_body属性
                func["function_body"] = func_body
            return callee_functions
    return None

# find_current_function
# 找到当前sourcelocation所在的函数
# return: function_name
def find_current_function(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # 检查source_location是否合法
    if not re.match(r'^[\w/]+\.c:\d+$', source_location) and not re.match(r'^[\w/]+\.h:\d+$', source_location):
        print(f"Invalid source location format: {source_location}")
        return None
    command_caller = CommandCaller()
    res = command_caller.call_graph_reader("find-function-body", source_location, os.path.join(PUT_ROOT_PATH, f"{PROJECT_NAME}.bc"))
    if res:
        res_json = json.loads(res)
        error = res_json.get("error", None)
        if error:
            # TODO 说明错误
            print(error)
        else:
            # 删除error属性
            del res_json["error"]
            func_body = dump_source_file(res_json["filename"], res_json['start_line'], res_json['end_line'])
            # 为func添加func_body属性
            res_json["function_body"] = func_body
            return res_json
    return None

'''
structure ctags
'''

# ctags_readtags
# 用ctag找到指定某个标识符的所有出现位置
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

'''
structure variable
'''

# find_var_definitions
# 找到指定变量所有被定义的位置
# return: list < source_location >
def find_var_definitions(source_location, var_name):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return []

# find_var_decl
# 找到变量声明的位置
# return: source_location: 'memcached/slab_automove.c:37'
def find_var_decl(source_location, var_name):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None


'''
path condition
'''

# get_path_constraint
# 找到当前source_location的路径约束条件的表达式
# return: exp
def get_path_constraint(source_location):
    # 基于LLVM来实现不要使用基于文本的查找
    # libclang
    return None

# check_always_implying、
# 检测两个表达式是否总是蕴含关系
# exp1  exp2
# return: bool
def check_always_implying(exp1, exp2):
    # 基于求解器来实现
    return None

'''
bound
'''


# check_le
# 检测两个表达式exp1 <= exp2是否恒成立
# exp1  exp2
# return: bool
def check_le(exp1, exp2):
    # 基于求解器来实现
    return None

'''
context
'''

# dump_source_file
# 按行号寻找指定代码片段
# return: string
def dump_source_file(file_name, start_line, end_line):
    start_line = int(start_line)
    end_line = int(end_line)

    file_path = os.path.join(PUT_ROOT_PATH, PROJECT_NAME, file_name)
    with open(file_path, "r") as f:
        lines = f.readlines()
        return "".join(lines[start_line - 1:end_line])
    return None

def dump_source_line(file_name, line_number):
    line_number = int(line_number)

    file_path = os.path.join(PUT_ROOT_PATH, PROJECT_NAME, file_name)
    with open(file_path, "r") as f:
        lines = f.readlines()
        return lines[line_number - 1].strip()
    return None

if __name__ == '__main__':
    # printFunctionCallSites(icfg, "stats_prefix_record_get");
    # print(find_callers("stats_prefix_record_get"))
    # printCalleeFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    print(find_callee("stats_prefix.c:118"))
    # printFunctionBodyByLocation(icfg, "stats_prefix.c:118");
    # print(find_current_function("stats_prefix.c:118"))
    #
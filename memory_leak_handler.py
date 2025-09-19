import os

import utils
from memory_defect import NeverFree
from memory_defect import PartialLeak
from memory_defect import MemoryLeak



def read_alter_file(alter_file_path, alter_file_name):
    memory_leak_list = []
    project_name = alter_file_name.split("_")[0]
    with open(os.path.join(alter_file_path, alter_file_name), 'r') as f:
        total_lines = len(f.readlines())
        f.seek(0)
        for i in range(total_lines):
            # 获取第i行
            line = f.readline().strip()
            if line.startswith("NeverFree"):
                # NeverFree : memory allocation at : (CallICFGNode: { "ln": 118, "cl": 11, "fl": "stats_prefix.c" })
                node_detail = line.split("{")[1].split("}")[0]
                file_name = node_detail.split("\"fl\": ")[1].strip().replace("\"", "")
                file_path = utils.find_file_path(project_name, file_name)
                line_number = node_detail.split("\"ln\": ")[1].strip().split(",")[0].strip().replace("\"", "")
                memory_leak_list.append(NeverFree(file_path+":"+line_number))
                # show the file path and line number
                # print(memory_leak_list[-1].get_source_location())
            elif line.startswith("PartialLeak"):
                # TODO: 处理PartialLeak
                node_detail = line.split("{")[1].split("}")[0]
                file_name = node_detail.split("\"fl\": ")[1].strip().replace("\"", "")
                file_path = utils.find_file_path(project_name, file_name)
                line_number = node_detail.split("\"ln\": ")[1].strip().split(",")[0].strip().replace("\"", "")
                # 下一行为提示信息忽略
                f.readline()
                # 后续的数行是conditional free path
                # 读取后面数行直到遇到空行或文件结尾
                conditional_free_paths = []
                while True:
                    line = f.readline().strip()
                    if line.startswith("-->"):
                        # 处理conditional free path
                        line = line.split("--> ")[1].strip()
                        cond = line.split("|")[1].strip().split(")")[0].strip()
                        cond_path_detail = line.split("{")[1].split("}")[0]
                        cond_file_name = cond_path_detail.split("\"fl\": ")[1].strip().replace("\"", "")
                        cond_file_path = utils.find_file_path(project_name, cond_file_name)
                        cond_line_number = cond_path_detail.split("\"ln\": ")[1].strip().split(",")[0].strip().replace("\"", "")
                        conditional_path = PartialLeak.conditional_path(cond, cond_file_path+":"+cond_line_number)
                        conditional_free_paths.append(conditional_path)    
                    elif not line.strip():
                        break
                    pass
                memory_leak_list.append(PartialLeak(file_path+":"+line_number, conditional_free_paths))

def handle_memory_leak(file_path, file_name):
    utils.extract_alter(file_path, file_name)
    alter_file_path = os.path.join(file_path, file_name.replace('.txt', '_alter.txt'))


read_alter_file("SARIF", "memcached_alter.txt")
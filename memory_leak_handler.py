import os
import re
import json

import utils
from memory_defect import NeverFree
from memory_defect import PartialLeak
from memory_defect import MemoryLeak
from alter_handler import AlterHandler
from llm_rag import resposeToAlter
from analysis_operators import find_callers
from analysis_operators import find_callee
from analysis_operators import find_current_function
from analysis_operators import dump_source_file
from analysis_operators import dump_source_line

PUT_ROOT_PATH = "PUT"
PROJECT_NAME = "memcached"

class MemoryLeakHandler(AlterHandler):
    def __init__(self):
        super().__init__()
    # TODO: 设定分析函数
    LEAK_RE = re.compile(
        r"^\s*(NeverFree|PartialLeak)\s*:\s*memory allocation at\s*:\s*\(CallICFGNode:\s*({.*})\)"
    )
    COND_PATH_RE = re.compile(
        r"^\s*-->\s*\(\s*({.*?})\s*\|\s*(.*?)\s*\)"
    )

    def _parse_location(self, project_name, node_detail_str):
        """Parses location details from a JSON-like string and returns a formatted location string."""
        try:
            # The detail string is not a valid JSON object, needs enclosing braces.
            details = json.loads(node_detail_str)
            file_name = details.get("fl")
            line_number = details.get("ln")

            if not file_name or line_number is None:
                return None

            file_path = utils.find_file_path(project_name, file_name)
            return f"{file_path}:{line_number}" if file_path else None
        except (json.JSONDecodeError, AttributeError):
            # Log error or handle cases where parsing fails.
            return None

    def read_alter_file(self, alter_file_path, alter_file_name):
        memory_leak_list = []
        project_name = alter_file_name.split("_")[0].split(".")[0]
        full_path = os.path.join(alter_file_path, alter_file_name)

        if not os.path.exists(full_path):
            return memory_leak_list

        with open(full_path, 'r') as f:
            lines = iter(f)
            for line in lines:
                line = line.strip()
                leak_match = self.LEAK_RE.match(line)
                if not leak_match:
                    continue

                leak_type, node_detail_str = leak_match.groups()
                location = self._parse_location(project_name, node_detail_str)
                if not location:
                    continue

                if leak_type == "NeverFree":
                    memory_leak_list.append(NeverFree(location))
                elif leak_type == "PartialLeak":
                    try:
                        # Skip the hint line
                        next(lines)
                    except StopIteration:
                        break

                    conditional_free_paths = []
                    while True:
                        try:
                            cond_line = next(lines).strip()
                            if not cond_line:
                                # Blank line signifies the end of this PartialLeak's conditional paths
                                break

                            cond_match = self.COND_PATH_RE.match(cond_line)
                            if cond_match:
                                cond_node_detail_str, cond = cond_match.groups()
                                cond_location = self._parse_location(project_name, cond_node_detail_str)
                                if cond_location:
                                    conditional_path = PartialLeak.conditional_path(cond, cond_location)
                                    conditional_free_paths.append(conditional_path)
                        except StopIteration:
                            break # End of file
                    memory_leak_list.append(PartialLeak(location, conditional_free_paths))
        self.alter_list = memory_leak_list
        return memory_leak_list

    def handle_memory_leak(self):
        # 处理当前alter_list中的每个alter
        for alter in self.alter_list:
            # print(alter.to_prompt())
            # user_prompt = "source code stats_prefix.c:118 " + dump_source_file(alter.get_source_location(), 118, 118) + "\n"
            # user_prompt += "source code is inside function stats_prefix.c:114-123 " + dump_source_file(alter.get_source_location(), 114, 123) + "\n"
            # user_prompt += "called function stats_prefix_find stats_prefix.c:37-87: " + dump_source_file(alter.get_source_location(), 37, 87) + "\n"
            # print(user_prompt)
            source_location = alter.get_source_location()
            # source_location前面如果有项目目录 删除
            if source_location.startswith(PROJECT_NAME + "/"):
                source_location = source_location[len(PROJECT_NAME) + 1:]
            user_prompt = f"source code at {source_location} : " + dump_source_line(source_location.split(":")[0], source_location.split(":")[1])+ "\n"
            # 给出source_location所在的函数
            current_function = find_current_function(source_location)
            if current_function:
                user_prompt += "source code is inside function " + current_function["function_name"] + " "
                user_prompt += current_function["function_body"] + "\n"
            # 给出当前行调用了什么函数
            callee_functions = find_callee(source_location)
            # print(callee_functions)
            for callee in callee_functions if callee_functions else []:
                user_prompt += "source code called function " + callee["function_name"] + " "
                user_prompt += callee["function_body"] + "\n"
            # if callee_functions:
            #     user_prompt += "this line called functions: " + ", ".join(callee_functions) + "\n"
            # 给出被调用函数的函数体
            # for callee in find_callee(current_function["function_name"]):
            #     user_prompt += "called function " + callee["function_name"] + " "
            #     user_prompt += callee["function_body"] + "\n"
            # print(user_prompt)
            response = resposeToAlter(alter.to_prompt(), user_prompt=user_prompt)
            print(response)
        return


if __name__ == '__main__':
    handler = MemoryLeakHandler()
    handler.read_alter_file(r"SARIF", "memcached_NEVERFREETEST.txt")
    handler.handle_memory_leak()
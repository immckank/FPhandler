import os
import re
import json
import sys

from memory_defect import NeverFree, DoubleFree, PartialLeak

from config import *
from utils import *

class AlterAnalyzer():
    def __init__(self):
        # if LLM_TYPE == "Gemini":
        #     self.analyzer = Gemini(model_name="gemini-2.5-flash")
        # elif LLM_TYPE == "DeepSeek":
        #     self.analyzer = DeepSeek(model_name="deepseek-chat")
        # else:
        #     raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
        self.alter_list = []
        self.alter_file_name = None
        self.LEAK_RE = re.compile(
            r"^\s*(NeverFree|PartialLeak|Double Free)\s*:\s*memory allocation at\s*:\s*\(CallICFGNode:\s*({.*})\)"
        )
        self.COND_PATH_RE = re.compile(
            r"^\s*-->\s*\(\s*({.*?})\s*\|\s*(.*?)\s*\)"
        )

    def get_alter_list(self):
        return self.alter_list

    def _parse_location(self, node_detail_str):
        """Parses location details from a JSON-like string and returns a formatted location string."""
        try:
            # The detail string is not a valid JSON object, needs enclosing braces.
            details = json.loads(node_detail_str)
            file_name = details.get("fl")
            # 如果是形如dir/file.c的 取最后文件名
            # 给定什么形式就先保存什么形式 不要修改
            # if file_name:
            #     file_name = file_name.split('/')[-1]
            line_number = details.get("ln")
            if not file_name or line_number is None:
                return None
            return f"{file_name}:{line_number}"
        except (json.JSONDecodeError, AttributeError):
            # Log error or handle cases where parsing fails.
            return None

    def read_alter_file(self, alter_file_path, alter_file_name):
        self.alter_list = []
        self.alter_file_name = alter_file_name
        full_path = os.path.join(alter_file_path, alter_file_name)

        if not os.path.exists(full_path):
            return 

        with open(full_path, 'r') as f:
            lines = iter(f)
            for line in lines:
                line = line.strip()
                leak_match = self.LEAK_RE.match(line)
                if not leak_match:
                    continue

                leak_type, node_detail_str = leak_match.groups()
                # print(leak_type, node_detail_str)
                location = self._parse_location(node_detail_str)
                if not location:
                    continue

                if leak_type == "NeverFree":
                    self.alter_list.append(NeverFree(location))
                elif leak_type == "PartialLeak":
                    try:
                        # Skip the hint line
                        next(lines)
                    except StopIteration:
                        break

                    conditional_free_paths = []
                    while True:
                        try:
                            free_line = next(lines).strip()
                            if not free_line:
                                # Blank line signifies the end of this PartialLeak's conditional paths
                                break
                            cond_match = self.COND_PATH_RE.match(free_line)
                            if cond_match:
                                cond_node_detail_str, cond = cond_match.groups()
                                cond_location = self._parse_location(cond_node_detail_str)
                                if cond_location:
                                    conditional_path = PartialLeak.conditional_path(cond, cond_location)
                                    conditional_free_paths.append(conditional_path)
                        except StopIteration:
                            break # End of file
                    self.alter_list.append(PartialLeak(location, conditional_free_paths))
                elif leak_type=="Double Free":
                    double_free_paths = []
                    while True:
                        try:
                            free_line = next(lines).strip()
                            if not free_line:
                                # Blank line signifies the end of this DoubleFree's free paths
                                break
                            cond_match = self.COND_PATH_RE.match(free_line)
                            if cond_match:
                                cond_node_detail_str, cond = cond_match.groups()
                                cond_location = self._parse_location(cond_node_detail_str)
                                if cond_location:
                                    double_free_path = DoubleFree.double_path(cond, cond_location)
                                    double_free_paths.append(double_free_path)
                        except StopIteration:
                            break
                    self.alter_list.append(DoubleFree(location, double_free_paths))
        return self.alter_list

if __name__ == "__main__":
    pass
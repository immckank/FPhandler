import itertools

from memory_defect import NeverFree, DoubleFree, PartialLeak, UseAfterFree
from utils import *

class AlterAnalyzer():
    def __init__(self):
        self.alter_list = []
        self.alter_file_name = None
        self.LEAK_RE = re.compile(
            r"^\s*(NeverFree|PartialLeak|Double Free|Use After Free)\s*:\s*memory allocation at\s*:\s*\(CallICFGNode:\s*({.*})\)"
        )
        self.COND_PATH_RE = re.compile(
            r"^\s*-->\s*\(\s*({.*?})\s*\|\s*(.*?)\s*\)"
        )
        self.FREE_RE = re.compile(
            r"^\s*Free at :\s*\(CallICFGNode:\s*({.*})\)"
        )
        self.USE_RE = re.compile(
            r"^\s*Use at :\s*\(\s*({.*?})\)"
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
            if file_name:
                file_name = file_name.split('/')[-1]
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
                # 如果location中包含路径 只去最后的部分
                
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
                elif leak_type == "Use After Free":
                    nodes_pairs = []

                    # 跳过内存分配行后的所有空行
                    while True:
                        try:
                            line = next(lines).strip()
                            if line:
                                lines = itertools.chain([line], lines)
                                break
                        except StopIteration:
                            break

                    # 收集所有free-use事件对
                    while True:
                        try:
                            free_line = next(lines).strip()
                            if not free_line:
                                continue

                            free_match = self.FREE_RE.match(free_line)
                            if not free_match:
                                lines = itertools.chain([free_line], lines)
                                break

                            free_node_detail_str = free_match.group(1)
                            free_location = self._parse_location(free_node_detail_str)

                            try:
                                free_path_line = next(lines).strip()
                                if free_path_line != "free path:":
                                    lines = itertools.chain([free_path_line], lines)
                            except StopIteration:
                                break

                            # 收集该free位置对应的所有use位置和条件路径
                            use_nodes = []  # 存储UseNode对象
                            while True:
                                try:
                                    use_line = next(lines).strip()
                                    if not use_line:
                                        continue

                                    use_match = self.USE_RE.match(use_line)
                                    if not use_match:
                                        lines = itertools.chain([use_line], lines)
                                        break

                                    use_node_detail_str = use_match.group(1)
                                    use_location = self._parse_location(use_node_detail_str)

                                    try:
                                        use_path_line = next(lines).strip()
                                        if use_path_line != "use path:":
                                            lines = itertools.chain([use_path_line], lines)

                                        condition = None
                                        condition_location = None
                                        try:
                                            cond_line = next(lines).strip()
                                            cond_match = self.COND_PATH_RE.match(cond_line)
                                            if cond_match:
                                                cond_node_detail_str, cond = cond_match.groups()
                                                condition_location = self._parse_location(cond_node_detail_str)
                                                condition = cond
                                        except StopIteration:
                                            pass
                                    except StopIteration:
                                        break

                                    if use_location:
                                        # 创建UseNode对象而不是元组
                                        use_node = UseAfterFree.UseNode(
                                            use_location=use_location,
                                            condition=condition,
                                            condition_location=condition_location
                                        )
                                        use_nodes.append(use_node)

                                except StopIteration:
                                    break

                            if free_location and use_nodes:
                                node_pair = UseAfterFree.NodePair(free_location, use_nodes)
                                nodes_pairs.append(node_pair)

                        except StopIteration:
                            break

                    if nodes_pairs:
                        self.alter_list.append(UseAfterFree(location, nodes_pairs))

                return self.alter_list


if __name__ == "__main__":
    analyzer = AlterAnalyzer()
    alter_list = analyzer.read_alter_file("ALTER_EXAMPLE", "use_after_free.txt")
    for alter in alter_list:
        print(alter.to_prompt())
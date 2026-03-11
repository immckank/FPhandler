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
        self.ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

    def get_alter_list(self):
        return self.alter_list

    def _parse_location(self, node_detail_str):
        """
        Parses CallICFGNode JSON to structured location {"fl", "ln", "cl"?}.
        Keeps fl as given (may be relative path); cl optional from SAR.
        """
        try:
            details = json.loads(node_detail_str)
            fl = details.get("fl")
            ln = details.get("ln")
            if not fl or ln is None:
                return None
            out = {"fl": fl, "ln": int(ln)}
            cl = details.get("cl")
            if cl is not None:
                out["cl"] = int(cl)
            return out
        except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
            return None

    def read_alter_file(self, sar_path):
        """sar_path: SAR 文件完整路径（与 config.SAR_PATH 一致）。"""
        self.alter_list = []
        self.alter_file_name = os.path.basename(sar_path)
        full_path = sar_path

        if not os.path.exists(full_path):
            return 

        with open(full_path, 'r') as f:
            lines = iter(f)
            for line in lines:
                line = line.strip()
                line = self.ANSI_ESCAPE.sub('', line).strip()
                leak_match = self.LEAK_RE.match(line)
                if not leak_match:
                    continue

                leak_type, node_detail_str = leak_match.groups()
                source_loc = self._parse_location(node_detail_str)
                if not source_loc:
                    continue

                if leak_type == "NeverFree":
                    self.alter_list.append(NeverFree(source_loc))
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
                                cond_loc = self._parse_location(cond_node_detail_str)
                                if cond_loc:
                                    conditional_path = PartialLeak.conditional_path(cond, cond_loc)
                                    conditional_free_paths.append(conditional_path)
                        except StopIteration:
                            break # End of file
                    self.alter_list.append(PartialLeak(source_loc, conditional_free_paths))
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
                                cond_loc = self._parse_location(cond_node_detail_str)
                                if cond_loc:
                                    double_free_path = DoubleFree.double_path(cond, cond_loc)
                                    double_free_paths.append(double_free_path)
                        except StopIteration:
                            break
                    self.alter_list.append(DoubleFree(source_loc, double_free_paths))
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
                            free_loc = self._parse_location(free_node_detail_str)

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
                                    use_loc = self._parse_location(use_node_detail_str)

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
                                                condition_loc = self._parse_location(cond_node_detail_str)
                                                condition = cond
                                        except StopIteration:
                                            pass
                                    except StopIteration:
                                        break

                                    if use_loc:
                                        use_node = UseAfterFree.UseNode(
                                            use_loc=use_loc,
                                            condition=condition,
                                            condition_loc=condition_loc,
                                        )
                                        use_nodes.append(use_node)

                                except StopIteration:
                                    break

                            if free_loc and use_nodes:
                                node_pair = UseAfterFree.NodePair(free_loc, use_nodes)
                                nodes_pairs.append(node_pair)

                        except StopIteration:
                            break

                    if nodes_pairs:
                        self.alter_list.append(UseAfterFree(source_loc, nodes_pairs))

        return self.alter_list


if __name__ == "__main__":
    analyzer = AlterAnalyzer()
    alter_list = analyzer.read_alter_file(os.path.join("ALTER_EXAMPLE", "use_after_free.txt"))
    for alter in alter_list:
        print(alter.to_prompt())
import itertools

from memory_defect import (
    NeverFree,
    DoubleFree,
    PartialLeak,
    UseAfterFree,
    BufferOverflow,
    UninitUse,
)
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
        self.BOF_HEADER_RE = re.compile(
            r"\[BufferOverflowChecker\]\s*(?:Buffer Overflow Error detected!|(?:MUST|MAY) buffer overflow)"
        )
        self.BOF_BASE_VALVAR_RE = re.compile(
            r"^\s*Base\s*:?\s*ValVar ID:\s*(\d+)\s*$"
        )
        self.BOF_DBG_LOC_RE = re.compile(
            r'\{\s*"(?:ln|line)"\s*:\s*(\d+)\s*,\s*"(?:cl|col)"\s*:\s*(\d+)\s*,\s*"(?:fl|file)"\s*:\s*"([^"]+)"\s*\}'
        )
        self.BOF_ACCESS_RE = re.compile(r"^\s*Access\s*:?\s*(.+)\s*$")
        self.BOF_VALID_RANGE_RE = re.compile(
            r"^\s*Valid range\s*:?\s*(.+?)(?:\s+\((\w+)\))?\s*$"
        )
        self.BOF_LOCATION_RE = re.compile(
            r'^\s*Location\s*:?\s*(\{.*\})\s*$'
        )
        self.BOF_BUFFER_INDEX_RE = re.compile(r"^\s*Buffer index:\s*(.+)\s*$")
        self.BOF_BUFFER_SIZE_RE = re.compile(r"^\s*Buffer size:\s*(.+)\s*$")
        self.UNINIT_HEADER_RE = re.compile(
            r"^\s*Uninit use\s*:\s*memory allocation at\s*:\s*\(\s*(.*)\s*\)\s*$"
        )
        self.UNINIT_USE_LINE_RE = re.compile(r"^\s*Use at :\s*\(\s*(.*)\s*\)\s*$")
        self.UNINIT_COND_PATH_RE = re.compile(
            r"^\s*-->\s*\(\s*(?:CallICFGNode:\s*)?(\{.*\})\s*\|\s*(.*?)\s*\)\s*$"
        )

    def get_alter_list(self):
        return self.alter_list

    def _extract_json_blob(self, s):
        s = (s or "").strip()
        if s.startswith("CallICFGNode:"):
            s = s[len("CallICFGNode:") :].strip()
        if s.startswith("(") and s.endswith(")"):
            s = s[1:-1].strip()
        return s

    def _parse_location(self, node_detail_str):
        """
        Parses CallICFGNode JSON to structured location {"fl", "ln", "cl"?}.
        Keeps fl as given (may be relative path); cl optional from SAR.
        """
        try:
            details = json.loads(self._extract_json_blob(node_detail_str))
            fl = details.get("fl") or details.get("file")
            ln = details.get("ln")
            if ln is None:
                ln = details.get("line")
            if not fl or ln is None:
                return None
            out = {"fl": fl, "ln": int(ln)}
            cl = details.get("cl")
            if cl is None:
                cl = details.get("col")
            if cl is not None:
                out["cl"] = int(cl)
            return out
        except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
            return None

    def _loc_from_dbg_text(self, text):
        m = self.BOF_DBG_LOC_RE.search(text)
        if not m:
            return None
        return {"fl": m.group(3), "ln": int(m.group(1)), "cl": int(m.group(2))}

    def _parse_bof_entry(self, lines):
        """
        在已匹配 [BufferOverflowChecker] 头行之后，从同一迭代器读取一条 BOF 记录。
        兼容旧版 Buffer index/size 与新版 Access/Valid range/Location 格式。
        """
        val_var_id = None
        ir_instruction = None
        source_loc = None
        buf_idx = None
        buf_size = None
        location_line = None

        try:
            while True:
                nl = next(lines)
                nl = self.ANSI_ESCAPE.sub("", nl).strip()
                if not nl:
                    continue
                if self.BOF_HEADER_RE.search(nl):
                    lines = itertools.chain([nl], lines)
                    break
                m_base = self.BOF_BASE_VALVAR_RE.match(nl)
                if m_base:
                    val_var_id = int(m_base.group(1))
                    continue
                m_dbg = self.BOF_DBG_LOC_RE.search(nl)
                if m_dbg and ir_instruction is None:
                    ir_instruction = nl.strip()
                    if source_loc is None:
                        source_loc = self._loc_from_dbg_text(nl)
                    continue
                m_loc = self.BOF_LOCATION_RE.match(nl)
                if m_loc:
                    location_line = m_loc.group(1)
                    loc = self._parse_location(location_line)
                    if loc:
                        source_loc = loc
                    continue
                m_acc = self.BOF_ACCESS_RE.match(nl)
                if m_acc and buf_idx is None:
                    buf_idx = m_acc.group(1).strip()
                    continue
                m_val = self.BOF_VALID_RANGE_RE.match(nl)
                if m_val and buf_size is None:
                    buf_size = m_val.group(1).strip()
                    if m_val.group(2):
                        buf_size += f" ({m_val.group(2)})"
                    if source_loc is not None:
                        break
                    continue
                m_idx = self.BOF_BUFFER_INDEX_RE.match(nl)
                if m_idx and buf_idx is None:
                    buf_idx = m_idx.group(1).strip()
                    continue
                m_sz = self.BOF_BUFFER_SIZE_RE.match(nl)
                if m_sz and buf_size is None:
                    buf_size = m_sz.group(1).strip()
                    if source_loc is not None:
                        break
        except StopIteration:
            pass

        if source_loc is None:
            return None

        return BufferOverflow(
            source_loc,
            val_var_id=val_var_id,
            ir_instruction=ir_instruction,
            buffer_index_text=buf_idx,
            buffer_size_text=buf_size,
        )

    def _parse_uninit_entry(self, line, lines):
        """
        解析一条 Uninit use 块（当前行已为 header）。无有效 fl/ln 的条目返回 None（丢弃）。
        分配点与所有 use 均无位置时跳过。
        """
        m = self.UNINIT_HEADER_RE.match(line)
        if not m:
            return None
        inner = (m.group(1) or "").strip()
        alloc_loc = self._parse_location(inner) if inner else None
        use_locs = []
        path_conditions = []
        while True:
            try:
                raw = next(lines)
            except StopIteration:
                break
            ul = self.ANSI_ESCAPE.sub("", raw).strip()
            if not ul:
                break
            cm = self.UNINIT_COND_PATH_RE.match(ul)
            if cm:
                cond_loc = self._parse_location(cm.group(1))
                if cond_loc:
                    path_conditions.append((cm.group(2).strip(), cond_loc))
                continue
            um = self.UNINIT_USE_LINE_RE.match(ul)
            if not um:
                lines = itertools.chain([raw], lines)
                break
            u_inner = (um.group(1) or "").strip()
            if not u_inner:
                continue
            loc = self._parse_location(u_inner)
            if loc:
                use_locs.append(loc)
        primary = None
        if normalize_source_loc(alloc_loc):
            primary = alloc_loc
        elif use_locs:
            primary = use_locs[0]
        if primary is None:
            return None
        return UninitUse(
            primary, alloc_loc=alloc_loc, use_sites=use_locs, path_conditions=path_conditions
        )

    def read_alter_file(self, sar_path):
        """sar_path: SAR 文件完整路径（与 config.SAR_PATH 一致）。"""
        self.alter_list = []
        self.alter_file_name = os.path.basename(sar_path)
        full_path = sar_path

        if not os.path.exists(full_path):
            return 

        with open(full_path, 'r') as f:
            lines = iter(f)
            # 必须用 next(lines) 驱动外层循环：内层会把未消费行 chain 回 lines，
            # 若用 for line in lines，迭代器在循环入口已固定，推回的行永远不会再被外层读到。
            while True:
                try:
                    raw_line = next(lines)
                except StopIteration:
                    break
                line = raw_line.strip()
                line = self.ANSI_ESCAPE.sub('', line).strip()
                leak_match = self.LEAK_RE.match(line)
                if not leak_match:
                    if self.BOF_HEADER_RE.search(line):
                        bof = self._parse_bof_entry(lines)
                        if bof:
                            self.alter_list.append(bof)
                    elif self.UNINIT_HEADER_RE.match(line):
                        uninit = self._parse_uninit_entry(line, lines)
                        if uninit:
                            self.alter_list.append(uninit)
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

                            while True:
                                try:
                                    path_line = next(lines).strip()
                                except StopIteration:
                                    break
                                if not path_line:
                                    break
                                if self.COND_PATH_RE.match(path_line):
                                    continue
                                lines = itertools.chain([path_line], lines)
                                break

                            # 收集该free位置对应的所有use位置和条件路径
                            use_nodes = []  # 存储UseNode对象
                            while True:
                                try:
                                    use_line = next(lines).strip()
                                    if not use_line:
                                        continue

                                    if self.COND_PATH_RE.match(use_line):
                                        continue

                                    use_match = self.USE_RE.match(use_line)
                                    if not use_match:
                                        lines = itertools.chain([use_line], lines)
                                        break

                                    use_node_detail_str = use_match.group(1)
                                    use_loc = self._parse_location(use_node_detail_str)

                                    condition = None
                                    condition_loc = None
                                    try:
                                        use_path_line = next(lines).strip()
                                        if use_path_line != "use path:":
                                            lines = itertools.chain([use_path_line], lines)
                                        while True:
                                            cond_line = next(lines).strip()
                                            if not cond_line:
                                                continue
                                            cond_match = self.COND_PATH_RE.match(cond_line)
                                            if not cond_match:
                                                lines = itertools.chain([cond_line], lines)
                                                break
                                            cond_node_detail_str, cond = cond_match.groups()
                                            parsed_cond_loc = self._parse_location(
                                                cond_node_detail_str
                                            )
                                            if parsed_cond_loc:
                                                condition_loc = parsed_cond_loc
                                                condition = cond
                                    except StopIteration:
                                        pass

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
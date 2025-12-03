from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


FunctionBodyResolver = Callable[[str], Optional[Dict[str, Any]]]
AstParser = Callable[[str], Tuple[Any, Optional[bytes]]]
LineDumper = Callable[[str, int], Optional[str]]


def _coerce_int(value: Any, *, default: int = 0) -> int:
    """Safely coerce arbitrary values to int with fallback."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class _CFGDependencies:
    find_function_body: FunctionBodyResolver
    parse_function_ast: AstParser
    dump_source_line: LineDumper


_CFG_DEPENDENCIES: Optional[_CFGDependencies] = None


def configure_function_cfg_dependencies(
    find_function_body: FunctionBodyResolver,
    parse_function_ast: AstParser,
    dump_source_line: LineDumper,
) -> None:
    """Registers the callbacks required by FunctionCFGAnalyzer."""
    global _CFG_DEPENDENCIES
    if not callable(find_function_body) or not callable(parse_function_ast) or not callable(dump_source_line):
        raise ValueError("All dependency callbacks must be callable.")
    _CFG_DEPENDENCIES = _CFGDependencies(
        find_function_body=find_function_body,
        parse_function_ast=parse_function_ast,
        dump_source_line=dump_source_line,
    )


def _resolve_dependencies(
    find_function_body: Optional[FunctionBodyResolver],
    parse_function_ast: Optional[AstParser],
    dump_source_line: Optional[LineDumper],
) -> _CFGDependencies:
    global _CFG_DEPENDENCIES
    if _CFG_DEPENDENCIES is None and any(
        dep is None for dep in (find_function_body, parse_function_ast, dump_source_line)
    ):
        raise RuntimeError(
            "FunctionCFGAnalyzer dependencies are not configured. "
            "Call configure_function_cfg_dependencies or provide the callbacks explicitly."
        )
    merged = _CFG_DEPENDENCIES or _CFGDependencies(
        find_function_body, parse_function_ast, dump_source_line  # type: ignore[arg-type]
    )
    return _CFGDependencies(
        find_function_body=find_function_body or merged.find_function_body,
        parse_function_ast=parse_function_ast or merged.parse_function_ast,
        dump_source_line=dump_source_line or merged.dump_source_line,
    )


class FunctionCFGAnalyzer:
    """Builds a CFG (Control Flow Graph) for a single function using tree-sitter AST."""

    def __init__(
        self,
        *,
        function_name: str,
        filename: str,
        function_start_line: int,
        function_end_line: int,
        body_node: Any,
        body_start_line: int,
        code_bytes: bytes,
        dump_source_line: LineDumper,
    ) -> None:
        self.function_name = function_name
        self.filename = filename
        self.function_start_line = function_start_line
        self.function_end_line = function_end_line
        self.body_node = body_node
        self.body_start_line = body_start_line
        self.code_bytes = code_bytes
        self._dump_source_line = dump_source_line

    @classmethod
    def from_function_name(
        cls,
        function_name: str,
        *,
        find_function_body: Optional[FunctionBodyResolver] = None,
        parse_function_ast: Optional[AstParser] = None,
        dump_source_line: Optional[LineDumper] = None,
    ) -> Optional["FunctionCFGAnalyzer"]:
        """Factory helper that loads the function body and prepares the analyzer."""
        if not isinstance(function_name, str) or not function_name.strip():
            logging.error("function_name must be a non-empty string")
            return None

        try:
            deps = _resolve_dependencies(find_function_body, parse_function_ast, dump_source_line)
        except RuntimeError as err:
            logging.error(str(err))
            return None

        func_meta = deps.find_function_body(function_name)
        if not func_meta or func_meta.get("error"):
            logging.error(f"Unable to locate function body for {function_name}")
            return None

        function_source = func_meta.get("function_body")
        if not isinstance(function_source, str) or not function_source.strip():
            logging.error(f"Function source for {function_name} is empty")
            return None

        filename = func_meta.get("filename", "")
        function_start_line = _coerce_int(func_meta.get("start_line"), default=0)
        function_end_line = _coerce_int(func_meta.get("end_line"), default=0)

        tree, code_bytes = deps.parse_function_ast(function_source)
        if tree is None or code_bytes is None:
            logging.error("tree-sitter is not available or failed to parse the function source")
            return None

        translation_unit = tree.root_node
        function_node = cls._find_function_definition(translation_unit)
        if function_node is None:
            logging.debug(
                "tree-sitter could not find explicit function definition for %s; "
                "scanning entire snippet instead.",
                function_name,
            )
            body_node = translation_unit
            body_start_line = function_start_line
        else:
            body_node = function_node.child_by_field_name("body") or translation_unit
            if body_node and body_node != translation_unit:
                body_offset = body_node.start_point[0]
                body_start_line = function_start_line + body_offset
            else:
                body_start_line = function_start_line

        if body_node is None:
            logging.error("Function body not found for %s", function_name)
            return None

        return cls(
            function_name=function_name,
            filename=filename,
            function_start_line=function_start_line,
            function_end_line=function_end_line,
            body_node=body_node,
            body_start_line=body_start_line,
            code_bytes=code_bytes,
            dump_source_line=deps.dump_source_line,
        )

    def build_cfg(self) -> Optional[Dict[str, Any]]:
        """Builds the CFG for the prepared function body."""
        if self.body_node is None or self.code_bytes is None:
            return None

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        next_node_id = 0

        entry_node = {
            "node_id": next_node_id,
            "type": "entry",
            "start_line": self.body_start_line,
            "end_line": self.body_start_line,
            "statements": [],
            "location": f"{self.filename}:{self.body_start_line}",
        }
        nodes.append(entry_node)
        entry_node_id = next_node_id
        next_node_id += 1

        basic_blocks = self._build_basic_blocks(start_node_id=next_node_id)
        next_node_id = basic_blocks.get("next_id", next_node_id)
        nodes.extend(basic_blocks.get("blocks", []))

        edges.extend(self._build_cfg_edges(basic_blocks, entry_node_id))

        exit_nodes = self._find_exit_nodes(basic_blocks.get("blocks", []))
        exit_line = self._determine_exit_line(exit_nodes, basic_blocks.get("blocks", []))

        exit_node_id = next_node_id
        exit_node = {
            "node_id": exit_node_id,
            "type": "exit",
            "start_line": exit_line,
            "end_line": exit_line,
            "statements": [],
            "location": f"{self.filename}:{exit_line}",
        }
        nodes.append(exit_node)
        next_node_id += 1

        for exit_n in exit_nodes:
            edges.append(
                {
                    "source": exit_n["node_id"],
                    "target": exit_node_id,
                    "type": "sequential",
                    "condition": None,
                }
            )

        blocks = basic_blocks.get("blocks", [])
        if blocks:
            last_block = blocks[-1]
            if (
                not self._block_ends_with_jump(last_block)
                and not any(e["source"] == last_block["node_id"] for e in edges)
            ):
                edges.append(
                    {
                        "source": last_block["node_id"],
                        "target": exit_node_id,
                        "type": "sequential",
                        "condition": None,
                    }
                )

            if last_block.get("type") == "label":
                if not any(
                    e["source"] == last_block["node_id"] and e["target"] == exit_node_id
                    for e in edges
                ):
                    edges.append(
                        {
                            "source": last_block["node_id"],
                            "target": exit_node_id,
                            "type": "sequential",
                            "condition": None,
                        }
                    )

            edges.insert(
                0,
                {
                    "source": entry_node_id,
                    "target": blocks[0]["node_id"],
                    "type": "sequential",
                    "condition": None,
                },
            )

        return {
            "function_name": self.function_name,
            "filename": self.filename,
            "nodes": nodes,
            "edges": edges,
        }

    @staticmethod
    def _find_function_definition(node: Any) -> Optional[Any]:
        if node.type == "function_definition":
            return node
        for child in getattr(node, "children", []):
            result = FunctionCFGAnalyzer._find_function_definition(child)
            if result:
                return result
        return None

    def _decode_source(self, node: Any) -> str:
        if node is None or self.code_bytes is None:
            return ""
        try:
            return self.code_bytes[node.start_byte : node.end_byte].decode("utf8").strip()
        except Exception:
            return ""

    def _extract_condition_expression(self, node: Any) -> Optional[str]:
        if node is None or self.code_bytes is None:
            return None

        condition_node = node.child_by_field_name("condition")
        if condition_node:
            return self._decode_source(condition_node)

        if node.type in ["if_statement", "while_statement", "for_statement", "do_statement"]:
            for child in node.children:
                if child.type == "parenthesized_expression":
                    return self._decode_source(child)
                if child.type == "condition":
                    return self._decode_source(child)
        return None

    def _block_ends_with_jump(self, block: Dict[str, Any]) -> bool:
        block_type = block.get("type")
        if block_type in {"return", "goto", "break", "continue"}:
            return True
        statements = block.get("statements") or []
        if not statements:
            return False
        tail = statements[-1].strip()
        return any(tail.startswith(keyword) for keyword in ("return", "goto", "break", "continue"))

    def _determine_exit_line(self, exit_nodes: List[Dict[str, Any]], blocks: List[Dict[str, Any]]) -> int:
        if exit_nodes:
            return max(exit.get("end_line", exit.get("start_line", self.body_start_line)) for exit in exit_nodes)
        if self.function_end_line:
            return self.function_end_line
        if blocks:
            last_block = blocks[-1]
            return last_block.get("end_line", last_block.get("start_line", self.body_start_line))
        return self.body_start_line

    def _find_exit_nodes(self, blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        exit_nodes: List[Dict[str, Any]] = []
        for block in blocks:
            if block.get("type") == "return":
                exit_nodes.append(block)
                continue
            statements = block.get("statements") or []
            if not statements:
                continue
            tail = statements[-1].strip()
            if tail.startswith("return") and not tail.startswith("return_"):
                exit_nodes.append(block)
        return exit_nodes

    def _find_block_after(self, blocks: List[Dict[str, Any]], start_id: Optional[int]) -> Optional[int]:
        if start_id is None:
            return None
        found = False
        for block in blocks:
            if found:
                return block["node_id"]
            if block["node_id"] == start_id:
                found = True
        return None

    def _ensure_line_coverage_blocks(self, blocks: List[Dict[str, Any]], next_node_id: int) -> int:
        if not blocks:
            return next_node_id

        covered: Set[int] = set()
        for block in blocks:
            start = block.get("start_line")
            end = block.get("end_line", start)
            if start is None:
                continue
            if end is None or end < start:
                end = start
            for line in range(start, end + 1):
                covered.add(line)

        coverage_start = max(self.function_start_line or 0, 1)
        existing_max = max((block.get("end_line") or block.get("start_line") or 0) for block in blocks)
        coverage_end = (
            self.function_end_line
            if self.function_end_line and self.function_end_line >= coverage_start
            else existing_max
        )
        if coverage_end < coverage_start:
            coverage_end = coverage_start

        placeholders: List[Dict[str, Any]] = []
        for line in range(coverage_start, coverage_end + 1):
            if line in covered:
                continue
            raw_line = self._dump_source_line(self.filename, line) or ""
            placeholders.append(
                {
                    "node_id": next_node_id,
                    "type": "placeholder",
                    "start_line": line,
                    "end_line": line,
                    "statements": [raw_line.strip("\n")],
                    "location": f"{self.filename}:{line}",
                }
            )
            next_node_id += 1

        if placeholders:
            blocks.extend(placeholders)
            blocks.sort(key=lambda b: (b.get("start_line", 0), b["node_id"]))

        return next_node_id

    def _build_cfg_edges(self, basic_blocks: Dict[str, Any], entry_node_id: int) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        blocks = basic_blocks.get("blocks", [])
        structure_map = basic_blocks.get("structure_map", [])
        goto_map = basic_blocks.get("goto_map", [])
        label_map = basic_blocks.get("label_map", {})

        if not blocks:
            return edges

        block_map = {block["node_id"]: block for block in blocks}
        handled_blocks: Set[int] = set()

        def resolve_existing_block(node_id: Optional[int]) -> Optional[int]:
            if node_id is None:
                return None
            if node_id in block_map:
                return node_id
            for candidate_id in sorted(block_map.keys()):
                if candidate_id >= node_id:
                    return candidate_id
            return None

        # Goto edges
        for goto_info in goto_map:
            goto_block_id = goto_info.get("block_id")
            target_label = goto_info.get("target_label")
            if goto_block_id is None or not target_label:
                continue
            target_node_id = label_map.get(target_label)
            if target_node_id is None:
                continue
            edges.append(
                {
                    "source": goto_block_id,
                    "target": target_node_id,
                    "type": "goto",
                    "condition": None,
                    "label": target_label,
                }
            )
            handled_blocks.add(goto_block_id)

        # Break/continue edges
        for block in blocks:
            block_type = block.get("type")
            if block_type not in {"break", "continue"}:
                continue
            block_id = block["node_id"]
            target_node_id: Optional[int] = None

            for structure in reversed(structure_map):
                s_type = structure.get("type")
                condition_id = structure.get("condition_id")
                if condition_id is None or block_id <= condition_id:
                    continue

                if s_type in {"while", "for", "do"}:
                    end_id = structure.get("loop_exit_id")
                elif s_type == "switch":
                    end_id = structure.get("switch_end_id")
                elif s_type == "if":
                    end_id = structure.get("if_end_id")
                else:
                    end_id = None

                if end_id is not None and block_id >= end_id:
                    continue

                if block_type == "break":
                    if s_type == "switch":
                        target_node_id = structure.get("switch_end_id")
                    elif s_type in {"while", "for", "do"}:
                        target_node_id = structure.get("loop_exit_id")
                elif block_type == "continue" and s_type in {"while", "for", "do"}:
                    target_node_id = structure.get("condition_id")

                if target_node_id:
                    target_node_id = resolve_existing_block(target_node_id)
                    break

            if target_node_id:
                edges.append(
                    {
                        "source": block_id,
                        "target": target_node_id,
                        "type": block_type,
                        "condition": None,
                    }
                )
                handled_blocks.add(block_id)

        # Control-structure edges
        for structure in structure_map:
            struct_type = structure.get("type")
            condition_id = structure.get("condition_id")
            condition_block = block_map.get(condition_id)
            if not condition_block:
                continue
            condition_expr = condition_block.get("condition")

            if struct_type == "if":
                then_start_id = structure.get("then_start_id")
                then_end_id = structure.get("then_end_id")
                then_ends_with_jump = structure.get("then_ends_with_jump", False)
                else_start_id = structure.get("else_start_id")
                else_end_id = structure.get("else_end_id")
                has_else = structure.get("has_else", False)
                if_end_id = structure.get("if_end_id")

                if then_end_id is None and then_start_id:
                    then_end_id = self._find_block_after(blocks, then_start_id)
                if else_end_id is None and else_start_id:
                    else_end_id = self._find_block_after(blocks, else_start_id)

                if if_end_id is None:
                    if else_end_id:
                        if_end_id = self._find_block_after(blocks, else_end_id)
                    elif then_end_id:
                        if_end_id = self._find_block_after(blocks, then_end_id)
                    if if_end_id is None:
                        if_end_id = self._find_block_after(blocks, condition_id)

                if then_start_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": then_start_id,
                            "type": "true_branch",
                            "condition": condition_expr,
                        }
                    )
                    handled_blocks.add(condition_id)

                    if not then_ends_with_jump and then_end_id and if_end_id:
                        then_end_block = block_map.get(then_end_id)
                        if then_end_block and not self._block_ends_with_jump(then_end_block):
                            edges.append(
                                {
                                    "source": then_end_id,
                                    "target": if_end_id,
                                    "type": "sequential",
                                    "condition": None,
                                }
                            )
                            handled_blocks.add(then_end_id)

                if else_start_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": else_start_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )
                elif has_else and if_end_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": if_end_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )
                    if else_end_id and not self._block_ends_with_jump(block_map.get(else_end_id, {})):
                        else_end_block = block_map.get(else_end_id)
                        if else_end_block:
                            edges.append(
                                {
                                    "source": else_end_id,
                                    "target": if_end_id,
                                    "type": "sequential",
                                    "condition": None,
                                }
                            )
                            handled_blocks.add(else_end_id)
                elif then_ends_with_jump and if_end_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": if_end_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )
                elif if_end_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": if_end_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )

            elif struct_type == "switch":
                case_labels = structure.get("case_labels", [])
                switch_end_id = structure.get("switch_end_id")
                switch_end_id = resolve_existing_block(switch_end_id)
                has_default = False

                for label in case_labels:
                    target_block_id = label.get("node_id")
                    if target_block_id is None:
                        for blk in blocks:
                            if blk.get("type") in {"case", "default"} and blk.get("start_line") == label.get("line"):
                                target_block_id = blk["node_id"]
                                break
                    if target_block_id is None:
                        continue
                    edges.append(
                        {
                            "source": condition_id,
                            "target": target_block_id,
                            "type": "switch_case",
                            "condition": label.get("value") or "default",
                        }
                    )
                    if label.get("value") == "default":
                        has_default = True

                if not has_default and switch_end_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": switch_end_id,
                            "type": "switch_case",
                            "condition": "default",
                        }
                    )
                handled_blocks.add(condition_id)

            elif struct_type in {"while", "for"}:
                body_start_id = structure.get("body_start_id")
                loop_exit_id = resolve_existing_block(structure.get("loop_exit_id"))

                if body_start_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": body_start_id,
                            "type": "loop_body",
                            "condition": condition_expr,
                        }
                    )
                if loop_exit_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": loop_exit_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )
                handled_blocks.add(condition_id)

                body_end_id = self._find_block_after(blocks, body_start_id)
                if body_end_id:
                    edges.append(
                        {
                            "source": body_end_id,
                            "target": condition_id,
                            "type": "loop_continue",
                            "condition": None,
                        }
                    )

            elif struct_type == "do":
                body_start_id = structure.get("body_start_id")
                condition_index = next((i for i, b in enumerate(blocks) if b["node_id"] == condition_id), -1)
                prev_block = blocks[condition_index - 1] if condition_index > 0 else None

                if prev_block:
                    edges.append(
                        {
                            "source": prev_block["node_id"],
                            "target": condition_id,
                            "type": "loop_continue",
                            "condition": None,
                        }
                    )
                    handled_blocks.add(prev_block["node_id"])

                if body_start_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": body_start_id,
                            "type": "loop_body",
                            "condition": condition_expr,
                        }
                    )
                next_block_id = self._find_block_after(blocks, condition_id)
                if next_block_id:
                    edges.append(
                        {
                            "source": condition_id,
                            "target": next_block_id,
                            "type": "false_branch",
                            "condition": condition_expr,
                        }
                    )
                handled_blocks.add(condition_id)

        # Sequential edges
        for idx in range(len(blocks) - 1):
            current_block = blocks[idx]
            next_block = blocks[idx + 1]
            current_id = current_block["node_id"]
            next_id = next_block["node_id"]

            if current_id in handled_blocks:
                continue
            if current_block.get("type") == "return":
                continue
            if self._block_ends_with_jump(current_block):
                continue
            if any(edge["source"] == current_id for edge in edges):
                continue
            if next_block.get("statements") == ["else"]:
                continue

            edges.append(
                {"source": current_id, "target": next_id, "type": "sequential", "condition": None}
            )

        return edges

    def _build_basic_blocks(self, start_node_id: int) -> Dict[str, Any]:
        blocks: List[Dict[str, Any]] = []
        structure_map: List[Dict[str, Any]] = []
        goto_map: List[Dict[str, Any]] = []
        label_map: Dict[str, int] = {}
        current_node_id = start_node_id

        current_block_statements: List[str] = []
        current_block_start_line: Optional[int] = None
        current_block_end_line: Optional[int] = None
        current_block_type = "normal"

        def add_current_block() -> Optional[int]:
            nonlocal current_block_statements, current_block_start_line, current_block_end_line, current_block_type, current_node_id
            if current_block_start_line is None:
                return None
            block = {
                "node_id": current_node_id,
                "type": current_block_type,
                "start_line": current_block_start_line,
                "end_line": current_block_end_line or current_block_start_line,
                "statements": list(current_block_statements),
                "location": f"{self.filename}:{current_block_start_line}",
            }
            blocks.append(block)
            block_id = current_node_id
            current_node_id += 1
            current_block_statements = []
            current_block_start_line = None
            current_block_end_line = None
            current_block_type = "normal"
            return block_id

        def emit_single_statement_block(
            stmt_text: str,
            line_no: int,
            block_type: str = "normal",
            end_line_no: Optional[int] = None,
        ) -> Optional[int]:
            nonlocal current_block_statements, current_block_start_line, current_block_end_line, current_block_type
            current_block_start_line = line_no
            current_block_end_line = end_line_no if end_line_no is not None else line_no
            current_block_statements = [stmt_text]
            current_block_type = block_type
            return add_current_block()

        def _link_switch_case(line_no: int, label_type: str, node_id: int) -> None:
            for structure in reversed(structure_map):
                if structure.get("type") != "switch":
                    continue
                for label in structure.get("case_labels", []):
                    if label.get("node_id") is not None:
                        continue
                    if label_type == "default":
                        if label.get("value") == "default" and label.get("line") == line_no:
                            label["node_id"] = node_id
                            return
                    else:
                        if label.get("value") != "default" and label.get("line") == line_no:
                            label["node_id"] = node_id
                            return

        def process_statement(node: Any, line_offset: int = 0) -> Optional[int]:
            nonlocal current_node_id, blocks, structure_map
            if node is None:
                return None

            line_no = self.function_start_line + node.start_point[0] + line_offset

            node_type = node.type

            if node_type == "if_statement":
                prev_block_id = add_current_block()
                condition = self._extract_condition_expression(node)
                branch_block_id = current_node_id
                branch_block = {
                    "node_id": branch_block_id,
                    "type": "branch",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [self._decode_source(node)],
                    "location": f"{self.filename}:{line_no}",
                    "condition": condition,
                    "control_structure": "if",
                }
                blocks.append(branch_block)
                current_node_id += 1

                then_node = node.child_by_field_name("consequence")
                then_start_id = None
                then_end_id = None
                then_ends_with_jump = False
                if then_node:
                    blocks_before_then = len(blocks)
                    stmts_before_then = len(current_block_statements)
                    then_start_id = process_statement(then_node)
                    blocks_after_then = len(blocks)
                    stmts_after_then = len(current_block_statements)
                    if then_start_id is None and stmts_after_then > stmts_before_then:
                        then_start_id = add_current_block()
                        blocks_after_then = len(blocks)
                    if then_start_id is None and blocks_after_then == blocks_before_then:
                        then_line_no = self.function_start_line + then_node.start_point[0]
                        then_block_id = current_node_id
                        then_block = {
                            "node_id": then_block_id,
                            "type": "normal",
                            "start_line": then_line_no,
                            "end_line": then_line_no,
                            "statements": [self._decode_source(then_node)],
                            "location": f"{self.filename}:{then_line_no}",
                        }
                        blocks.append(then_block)
                        current_node_id += 1
                        then_start_id = then_block_id
                        then_end_id = then_block_id
                    if blocks_after_then > blocks_before_then:
                        last_then_block = blocks[-1]
                        if self._block_ends_with_jump(last_then_block):
                            then_ends_with_jump = True
                        then_end_id = last_then_block["node_id"]
                    elif then_start_id:
                        then_end_id = then_start_id

                else_node = node.child_by_field_name("alternative")
                else_start_id = None
                else_end_id = None
                if else_node:
                    else_node_line = self.function_start_line + else_node.start_point[0]
                    if else_node.type == "compound_statement":
                        else_node_text = self._decode_source(else_node)[:1].strip()
                        if else_node_text == "{":
                            else_keyword_line = (
                                else_node_line - 1 if else_node_line > self.function_start_line else else_node_line
                            )
                        else:
                            else_keyword_line = else_node_line
                    else:
                        else_keyword_line = else_node_line

                    else_keyword_block_id = current_node_id
                    else_keyword_block = {
                        "node_id": else_keyword_block_id,
                        "type": "normal",
                        "start_line": else_keyword_line,
                        "end_line": else_keyword_line,
                        "statements": ["else"],
                        "location": f"{self.filename}:{else_keyword_line}",
                    }
                    blocks.append(else_keyword_block)
                    current_node_id += 1
                    else_start_id = else_keyword_block_id

                    blocks_before_else = len(blocks)
                    stmts_before_else = len(current_block_statements)
                    else_content_start_id = process_statement(else_node)
                    blocks_after_else = len(blocks)
                    stmts_after_else = len(current_block_statements)
                    if else_content_start_id is None and stmts_after_else > stmts_before_else:
                        flushed_id = add_current_block()
                        blocks_after_else = len(blocks)
                        if flushed_id is not None:
                            else_content_start_id = flushed_id
                    if blocks_after_else > blocks_before_else:
                        else_end_id = blocks[-1]["node_id"]
                    elif else_content_start_id is None and blocks_after_else == blocks_before_else:
                        if else_node.type == "compound_statement":
                            else_end_id = else_start_id
                        else:
                            else_line_no = self.function_start_line + else_node.start_point[0]
                            else_block_id = current_node_id
                            else_block = {
                                "node_id": else_block_id,
                                "type": "normal",
                                "start_line": else_line_no,
                                "end_line": else_line_no,
                                "statements": [self._decode_source(else_node)],
                                "location": f"{self.filename}:{else_line_no}",
                            }
                            blocks.append(else_block)
                            current_node_id += 1
                            else_end_id = else_block_id
                    elif else_content_start_id:
                        else_end_id = else_content_start_id
                    else:
                        else_end_id = else_start_id

                blocks_before_if_end = len(blocks)
                add_current_block()
                blocks_after_if_end = len(blocks)
                if_end_id = None
                if blocks_after_if_end > blocks_before_if_end:
                    if_end_id = blocks[-1]["node_id"]

                structure_map.append(
                    {
                        "type": "if",
                        "condition_id": branch_block_id,
                        "prev_id": prev_block_id,
                        "then_start_id": then_start_id,
                        "then_end_id": then_end_id,
                        "then_ends_with_jump": then_ends_with_jump,
                        "else_start_id": else_start_id,
                        "else_end_id": else_end_id,
                        "has_else": else_node is not None,
                        "if_end_id": if_end_id,
                    }
                )

                return branch_block_id

            if node_type == "while_statement":
                prev_block_id = add_current_block()
                condition = self._extract_condition_expression(node)
                loop_entry_id = current_node_id
                loop_entry_block = {
                    "node_id": loop_entry_id,
                    "type": "loop_entry",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [self._decode_source(node)],
                    "location": f"{self.filename}:{line_no}",
                    "condition": condition,
                    "control_structure": "while",
                }
                blocks.append(loop_entry_block)
                current_node_id += 1

                body_node_inner = node.child_by_field_name("body")
                body_start_id = process_statement(body_node_inner) if body_node_inner else None
                loop_exit_id = add_current_block()
                if loop_exit_id is None:
                    loop_exit_id = current_node_id

                structure_map.append(
                    {
                        "type": "while",
                        "condition_id": loop_entry_id,
                        "prev_id": prev_block_id,
                        "body_start_id": body_start_id,
                        "loop_exit_id": loop_exit_id,
                    }
                )
                return loop_entry_id

            if node_type == "for_statement":
                prev_block_id = add_current_block()
                condition = self._extract_condition_expression(node)
                loop_entry_id = current_node_id
                loop_entry_block = {
                    "node_id": loop_entry_id,
                    "type": "loop_entry",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [self._decode_source(node)],
                    "location": f"{self.filename}:{line_no}",
                    "condition": condition,
                    "control_structure": "for",
                }
                blocks.append(loop_entry_block)
                current_node_id += 1

                body_node_inner = node.child_by_field_name("body")
                body_start_id = process_statement(body_node_inner) if body_node_inner else None
                loop_exit_id = add_current_block()
                if loop_exit_id is None:
                    loop_exit_id = current_node_id

                structure_map.append(
                    {
                        "type": "for",
                        "condition_id": loop_entry_id,
                        "prev_id": prev_block_id,
                        "body_start_id": body_start_id,
                        "loop_exit_id": loop_exit_id,
                    }
                )
                return loop_entry_id

            if node_type == "do_statement":
                prev_block_id = add_current_block()
                body_node_inner = node.child_by_field_name("body")
                body_start_id = process_statement(body_node_inner) if body_node_inner else None
                condition = self._extract_condition_expression(node)
                loop_entry_id = current_node_id
                loop_entry_block = {
                    "node_id": loop_entry_id,
                    "type": "loop_entry",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [self._decode_source(node)],
                    "location": f"{self.filename}:{line_no}",
                    "condition": condition,
                    "control_structure": "do",
                }
                blocks.append(loop_entry_block)
                current_node_id += 1

                structure_map.append(
                    {
                        "type": "do",
                        "condition_id": loop_entry_id,
                        "prev_id": prev_block_id,
                        "body_start_id": body_start_id,
                    }
                )

                add_current_block()
                return loop_entry_id

            if node_type == "switch_statement":
                prev_block_id = add_current_block()
                condition = self._extract_condition_expression(node)
                switch_block_id = current_node_id
                switch_block = {
                    "node_id": switch_block_id,
                    "type": "switch",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [self._decode_source(node)],
                    "location": f"{self.filename}:{line_no}",
                    "condition": condition,
                }
                blocks.append(switch_block)
                current_node_id += 1

                case_labels: List[Dict[str, Any]] = []
                body_node_inner = node.child_by_field_name("body")
                if body_node_inner:
                    for child in body_node_inner.children:
                        if child.type == "case_statement":
                            case_line = self.function_start_line + child.start_point[0]
                            case_expr_node = child.child_by_field_name("value")
                            case_value = (
                                self.code_bytes[case_expr_node.start_byte : case_expr_node.end_byte]
                                .decode("utf8")
                                .strip()
                                if case_expr_node
                                else None
                            )
                            case_labels.append({"line": case_line, "value": case_value, "node_id": None})
                        elif child.type == "default_statement":
                            case_labels.append(
                                {
                                    "line": self.function_start_line + child.start_point[0],
                                    "value": "default",
                                    "node_id": None,
                                }
                            )

                switch_structure_entry = {
                    "type": "switch",
                    "condition_id": switch_block_id,
                    "prev_id": prev_block_id,
                    "case_labels": case_labels,
                    "switch_end_id": None,
                }
                structure_map.append(switch_structure_entry)
                if body_node_inner:
                    process_statement(body_node_inner)

                switch_end_id = add_current_block()
                if switch_end_id is None:
                    switch_end_line = self.function_start_line + (
                        body_node_inner.end_point[0] if body_node_inner else node.end_point[0]
                    )
                    switch_end_id = current_node_id
                    blocks.append(
                        {
                            "node_id": switch_end_id,
                            "type": "switch_end",
                            "start_line": switch_end_line,
                            "end_line": switch_end_line,
                            "statements": [],
                            "location": f"{self.filename}:{switch_end_line}",
                        }
                    )
                    current_node_id += 1

                switch_structure_entry["switch_end_id"] = switch_end_id
                return switch_block_id

            if node_type == "case_statement":
                add_current_block()
                stmt_text = self._decode_source(node)
                case_block_id = current_node_id
                case_block = {
                    "node_id": case_block_id,
                    "type": "case",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [stmt_text],
                    "location": f"{self.filename}:{line_no}",
                }
                blocks.append(case_block)
                current_node_id += 1
                _link_switch_case(line_no, "case", case_block_id)

                value_node = node.child_by_field_name("value")
                for child in node.children:
                    if child.type in ["case", ":", "default"]:
                        continue
                    if value_node and child.id == value_node.id:
                        continue
                    process_statement(child)
                return case_block_id

            if node_type == "default_statement":
                add_current_block()
                stmt_text = self._decode_source(node)
                default_block_id = current_node_id
                default_block = {
                    "node_id": default_block_id,
                    "type": "default",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [stmt_text],
                    "location": f"{self.filename}:{line_no}",
                }
                blocks.append(default_block)
                current_node_id += 1
                _link_switch_case(line_no, "default", default_block_id)

                for child in node.children:
                    if child.type in ["default", ":"]:
                        continue
                    process_statement(child)
                return default_block_id

            if node_type == "return_statement":
                add_current_block()
                return emit_single_statement_block(self._decode_source(node), line_no, "return")

            if node_type == "goto_statement":
                add_current_block()
                stmt_text = self._decode_source(node)
                target_label = None
                for child in node.children:
                    if child.type == "identifier":
                        target_label = self.code_bytes[child.start_byte : child.end_byte].decode("utf8").strip()
                        break
                if not target_label:
                    match = re.match(r"goto\s+(\w+)\s*;", stmt_text)
                    if match:
                        target_label = match.group(1)
                goto_block_id = current_node_id
                goto_block = {
                    "node_id": goto_block_id,
                    "type": "normal",
                    "start_line": line_no,
                    "end_line": line_no,
                    "statements": [stmt_text],
                    "location": f"{self.filename}:{line_no}",
                }
                blocks.append(goto_block)
                current_node_id += 1

                if target_label:
                    goto_map.append(
                        {
                            "block_id": goto_block_id,
                            "target_label": target_label,
                            "location": f"{self.filename}:{line_no}",
                        }
                    )

                return goto_block_id

            if node_type in ["break_statement", "continue_statement"]:
                add_current_block()
                stmt_text = self._decode_source(node)
                block_type = "break" if node_type == "break_statement" else "continue"
                return emit_single_statement_block(stmt_text, line_no, block_type)

            if node_type == "compound_statement":
                first_id = None
                for child in node.children:
                    if child.type in ["{", "}"]:
                        continue
                    result_id = process_statement(child)
                    if first_id is None and result_id is not None:
                        first_id = result_id
                return first_id

            if node_type == "labeled_statement":
                add_current_block()
                label_name = None
                label_line_no = line_no

                for child in node.children:
                    if child.type == "statement_label":
                        for grandchild in child.children:
                            if grandchild.type == "identifier":
                                label_name = (
                                    self.code_bytes[grandchild.start_byte : grandchild.end_byte].decode("utf8").strip()
                                )
                                label_line_no = self.function_start_line + grandchild.start_point[0]
                                break
                        if label_name:
                            break
                    elif child.type == "identifier":
                        label_name = self.code_bytes[child.start_byte : child.end_byte].decode("utf8").strip()
                        label_line_no = self.function_start_line + child.start_point[0]
                        break
                    elif child.type == ":":
                        continue

                stmt_text = self._decode_source(node)
                if not label_name:
                    match = re.match(r"^(\w+)\s*:", stmt_text)
                    if match:
                        label_name = match.group(1)

                label_block_id = current_node_id
                label_block = {
                    "node_id": label_block_id,
                    "type": "label",
                    "start_line": label_line_no,
                    "end_line": label_line_no,
                    "statements": [stmt_text],
                    "location": f"{self.filename}:{label_line_no}",
                    "label_name": label_name,
                }
                blocks.append(label_block)

                if label_name:
                    label_map[label_name] = label_block_id

                current_node_id += 1

                body_node_inner = node.child_by_field_name("body")
                if body_node_inner:
                    process_statement(body_node_inner)
                else:
                    for child in node.children:
                        if child.type in ["statement_label", "identifier", ":", "statement_identifier"]:
                            continue
                        process_statement(child)
                        break

                return label_block_id

            if node_type in ["expression_statement", "declaration"]:
                add_current_block()
                stmt_text = self._decode_source(node)
                end_line_no = self.function_start_line + node.end_point[0] + line_offset
                return emit_single_statement_block(stmt_text, line_no, "normal", end_line_no)

            for child in node.children:
                process_statement(child)
            return None

        body_node = self.body_node
        if body_node is None or self.code_bytes is None:
            return {
                "blocks": blocks,
                "next_id": current_node_id,
                "structure_map": structure_map,
                "goto_map": goto_map,
                "label_map": label_map,
            }

        if body_node.type == "compound_statement":
            for child in body_node.children:
                if child.type in ["{", "}"]:
                    continue
                process_statement(child)
        else:
            process_statement(body_node)

        add_current_block()

        current_node_id = self._ensure_line_coverage_blocks(blocks, current_node_id)

        return {
            "blocks": blocks,
            "next_id": current_node_id,
            "structure_map": structure_map,
            "goto_map": goto_map,
            "label_map": label_map,
        }

    @staticmethod
    def _find_nodes_by_line(nodes: List[Dict[str, Any]], line_number: int, exclude_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Finds all nodes that contain the given line number.
        
        Args:
            nodes: List of node dictionaries
            line_number: Target line number
            exclude_types: List of node types to exclude (e.g., ["entry", "exit"])
            
        Returns:
            List of nodes that contain this line number
        """
        if exclude_types is None:
            exclude_types = []
        
        matching_nodes = []
        for node in nodes:
            node_type = node.get("type", "")
            if node_type in exclude_types:
                continue
                
            start_line = node.get("start_line", 0)
            end_line = node.get("end_line", 0)
            # Only match if the line is within the node's line range
            # For nodes with same start and end line, only match if exactly equal
            if start_line == end_line:
                if start_line == line_number:
                    matching_nodes.append(node)
            else:
                if start_line <= line_number <= end_line:
                    matching_nodes.append(node)
        
        # Sort by specificity: prefer nodes with smaller range that contain the line
        # Nodes where the line is closer to the start are preferred
        matching_nodes.sort(key=lambda n: (
            n.get("end_line", 0) - n.get("start_line", 0),  # Smaller range first
            abs(n.get("start_line", 0) - line_number)  # Closer to start line first
        ))
        
        return matching_nodes

    @staticmethod
    def _find_all_paths_dfs(
        start_id: int, 
        target_ids: Set[int], 
        graph: Dict[int, List[int]], 
        nodes: List[Dict[str, Any]], 
        edge_map: Dict, 
        visited: Optional[Set[int]] = None, 
        current_path: Optional[List[Dict[str, Any]]] = None,
        max_depth: int = 100, 
        max_paths: int = 1000
    ) -> List[List[Dict[str, Any]]]:
        """Uses DFS to find all paths from start to any target node.
        
        Args:
            start_id: Starting node ID
            target_ids: Set of target node IDs
            graph: Adjacency list representation of the graph
            nodes: List of all node dictionaries
            edge_map: Map from (source, target) to edge info
            visited: Set of visited nodes in current path (to detect cycles in current path)
            current_path: Current path being explored
            max_depth: Maximum path depth to prevent infinite loops
            max_paths: Maximum number of paths to find (to prevent explosion)
            
        Returns:
            List of paths, each path is a list of dictionaries with node and edge info
        """
        if visited is None:
            visited = set()
        if current_path is None:
            current_path = []
        
        # Check depth limit
        if len(current_path) >= max_depth:
            return []
        
        # Check if we've reached a target
        if start_id in target_ids:
            # Create a copy of current path with the target node
            node_map = {node["node_id"]: node for node in nodes}
            if start_id in node_map:
                final_path = current_path + [{"node": node_map[start_id], "edge": None}]
                return [final_path]
            return []
        
        # Check for cycles in current path (prevent infinite loops within same path)
        # But allow revisiting nodes in different paths
        if start_id in visited:
            return []  # Skip paths that form cycles within the same path
        
        # Get node info
        node_map = {node["node_id"]: node for node in nodes}
        if start_id not in node_map:
            return []
        
        current_node = node_map[start_id]
        paths = []
        
        # Mark current node as visited for this path
        new_visited = visited.copy()
        new_visited.add(start_id)
        
        # Check if current node is a loop entry node
        node_type = current_node.get("type", "")
        control_structure = current_node.get("control_structure", "")
        is_loop_entry = (node_type == "loop_entry")
        is_while_or_for = (control_structure in ["while", "for"])
        is_do_while = (control_structure == "do")
        
        # Explore neighbors
        neighbors = graph.get(start_id, [])
        
        # For loop nodes, filter and process edges specially
        if is_loop_entry:
            loop_body_edges = []
            loop_continue_edges = []
            other_edges = []
            
            # Categorize edges
            for neighbor_id in neighbors:
                edge_info = edge_map.get((start_id, neighbor_id), {})
                edge_type = edge_info.get("type", "unknown") if edge_info else "unknown"
                
                if edge_type == "loop_body":
                    loop_body_edges.append((neighbor_id, edge_info))
                elif edge_type == "loop_continue":
                    loop_continue_edges.append((neighbor_id, edge_info))
                else:
                    other_edges.append((neighbor_id, edge_info))
            
            # Process edges based on loop type
            if is_while_or_for:
                # while/for: two paths - enter loop once OR skip loop
                # Path 1: Enter loop body once (then skip loop_continue)
                for neighbor_id, edge_info in loop_body_edges:
                    # Mark loop as visited to prevent going through loop_continue back
                    loop_visited = new_visited.copy()
                    loop_visited.add(start_id)  # Mark loop entry as visited
                    
                    path_entry = {
                        "node": current_node,
                        "edge": edge_info
                    }
                    
                    # Recursively find paths, but skip loop_continue edges when we encounter the loop again
                    neighbor_paths = FunctionCFGAnalyzer._find_all_paths_dfs(
                        neighbor_id, target_ids, graph, nodes, edge_map,
                        loop_visited, current_path + [path_entry], max_depth
                    )
                    
                    paths.extend(neighbor_paths)
                
                # Path 2: Skip loop (use other edges like sequential/false branch)
                for neighbor_id, edge_info in other_edges:
                    path_entry = {
                        "node": current_node,
                        "edge": edge_info
                    }
                    
                    neighbor_paths = FunctionCFGAnalyzer._find_all_paths_dfs(
                        neighbor_id, target_ids, graph, nodes, edge_map,
                        new_visited, current_path + [path_entry], max_depth
                    )
                    
                    paths.extend(neighbor_paths)
            
            elif is_do_while:
                # do-while: one path - enter loop body once (then skip loop_continue)
                for neighbor_id, edge_info in loop_body_edges:
                    # Mark loop as visited to prevent going through loop_continue back
                    loop_visited = new_visited.copy()
                    loop_visited.add(start_id)  # Mark loop entry as visited
                    
                    path_entry = {
                        "node": current_node,
                        "edge": edge_info
                    }
                    
                    # Recursively find paths, but skip loop_continue edges when we encounter the loop again
                    neighbor_paths = FunctionCFGAnalyzer._find_all_paths_dfs(
                        neighbor_id, target_ids, graph, nodes, edge_map,
                        loop_visited, current_path + [path_entry], max_depth
                    )
                    
                    paths.extend(neighbor_paths)
        
        else:
            # Non-loop node: process all edges normally, but skip loop_continue if loop already visited
            for neighbor_id in neighbors:
                edge_info = edge_map.get((start_id, neighbor_id), {})
                edge_type = edge_info.get("type", "unknown") if edge_info else "unknown"
                
                # Skip loop_continue edge if we've already visited the target loop node
                if edge_type == "loop_continue":
                    # Check if target node (which should be a loop_entry) is already in visited
                    target_node = next((n for n in nodes if n["node_id"] == neighbor_id), None)
                    if target_node and target_node.get("type") == "loop_entry":
                        if neighbor_id in visited:
                            # Already visited this loop, skip the continue edge
                            continue
                
                path_entry = {
                    "node": current_node,
                    "edge": edge_info if edge_info else None
                }
                
                # Recursively find paths from neighbor
                neighbor_paths = FunctionCFGAnalyzer._find_all_paths_dfs(
                    neighbor_id, target_ids, graph, nodes, edge_map,
                    new_visited, current_path + [path_entry], max_depth
                )
                
                paths.extend(neighbor_paths)
        
        return paths

    @staticmethod
    def _remove_duplicate_paths(paths: List[List[Dict[str, Any]]]) -> List[List[Dict[str, Any]]]:
        """Removes duplicate paths based on node ID sequences.
        
        Args:
            paths: List of paths
            
        Returns:
            List of unique paths
        """
        seen = set()
        unique_paths = []
        
        for path in paths:
            # Create a signature from node IDs
            node_ids = tuple(entry["node"]["node_id"] for entry in path if "node" in entry)
            if node_ids not in seen:
                seen.add(node_ids)
                unique_paths.append(path)
        
        return unique_paths

    @classmethod
    def find_all_paths_in_cfg(
        cls, 
        function_name: str, 
        start_line: Any, 
        target_line: Any
    ) -> Optional[List[List[Dict[str, Any]]]]:
        """Finds all paths from a starting line to a target line in a function's control flow graph.
        
        Args:
            function_name: Name of the function
            start_line: Starting line number (int) or location string (e.g., "filename:line" or "839")
            target_line: Target line number (int) or location string (e.g., "filename:line" or "945")
            
        Returns:
            List of paths, where each path is a list of dictionaries representing nodes and edges.
            Each dictionary contains:
            - "node": node information (id, type, location, statements)
            - "edge": edge information (type, condition) if there's an edge to next node
            Returns None if the function or lines cannot be found.
        """
        # Extract line numbers if strings are provided
        def extract_line_number(line_input: Any) -> Optional[int]:
            if isinstance(line_input, int):
                return line_input
            if isinstance(line_input, str):
                # Try format "filename:line"
                if ":" in line_input:
                    try:
                        return int(line_input.split(":")[-1])
                    except ValueError:
                        pass
                # Try direct integer string
                try:
                    return int(line_input)
                except ValueError:
                    pass
            return None
        
        start_line_num = extract_line_number(start_line)
        target_line_num = extract_line_number(target_line)
        
        if start_line_num is None:
            logging.error(f"Invalid start_line format: {start_line}. Expected int or string like 'filename:line' or 'line'")
            return None
        if target_line_num is None:
            logging.error(f"Invalid target_line format: {target_line}. Expected int or string like 'filename:line' or 'line'")
            return None
        
        # Get CFG for the function
        analyzer = cls.from_function_name(function_name)
        if analyzer is None:
            logging.error(f"Failed to prepare CFG analyzer for {function_name}")
            return None

        cfg = analyzer.build_cfg()
        if not cfg:
            logging.error(f"Failed to build CFG for function {function_name}")
            return None
        
        nodes = cfg.get("nodes", [])
        edges = cfg.get("edges", [])
        
        # Find nodes containing the start and target lines
        # Exclude entry/exit nodes as they have incorrect line numbers
        start_nodes = cls._find_nodes_by_line(nodes, start_line_num, exclude_types=["entry", "exit"])
        target_nodes = cls._find_nodes_by_line(nodes, target_line_num, exclude_types=["entry", "exit"])
        
        if not start_nodes:
            logging.error(f"No node found containing line {start_line_num} in function {function_name}")
            return None
        if not target_nodes:
            logging.error(f"No node found containing line {target_line_num} in function {function_name}")
            # Debug: show available nodes
            available_lines = [(n["node_id"], n.get("type"), n.get("start_line"), n.get("end_line"), n.get("location")) 
                              for n in nodes if n.get("type") not in ["entry", "exit"]]
            logging.debug(f"Available nodes (excluding entry/exit): {available_lines[:10]}...")
            return None
        
        # Build adjacency list from edges (include ALL edges including sequential for path finding)
        graph: Dict[int, List[int]] = {}
        edge_map: Dict[Tuple[int, int], Dict[str, Any]] = {}  # (source, target) -> edge info
        for edge in edges:
            source = edge.get("source")
            target = edge.get("target")
            edge_type = edge.get("type", "sequential")
            
            # Include ALL edge types for path finding (sequential edges are needed for complete paths)
            if source not in graph:
                graph[source] = []
            if target not in graph[source]:  # Avoid duplicate edges
                graph[source].append(target)
            edge_map[(source, target)] = edge
        
        # Find all paths from any start node to any target node
        all_paths = []
        target_node_ids = {node["node_id"] for node in target_nodes}
        
        for start_node in start_nodes:
            start_id = start_node["node_id"]
            paths = cls._find_all_paths_dfs(start_id, target_node_ids, graph, nodes, edge_map, max_depth=100)
            all_paths.extend(paths)
        
        # Remove duplicate paths
        unique_paths = cls._remove_duplicate_paths(all_paths)
        
        return unique_paths if unique_paths else None

    @classmethod
    def find_all_paths_between_lines(
        cls, 
        function_name: str, 
        start_location: str, 
        target_location: str
    ) -> Optional[List[List[Dict[str, Any]]]]:
        """Finds all paths between two source locations in a function's CFG.
        
        Args:
            function_name: Name of the function
            start_location: Starting location in format 'filename:line_number' or just line number
            target_location: Target location in format 'filename:line_number' or just line number
            
        Returns:
            List of paths, where each path contains node and edge information.
            Returns None if paths cannot be found.
        """
        # Extract line numbers from locations
        def extract_line(location: str) -> Optional[int]:
            if isinstance(location, int):
                return location
            if isinstance(location, str):
                # Try format "filename:line"
                if ":" in location:
                    try:
                        return int(location.split(":")[-1])
                    except ValueError:
                        pass
                # Try direct integer
                try:
                    return int(location)
                except ValueError:
                    pass
            return None
        
        start_line = extract_line(start_location)
        target_line = extract_line(target_location)
        
        if start_line is None:
            logging.error(f"Invalid start_location format: {start_location}")
            return None
        if target_line is None:
            logging.error(f"Invalid target_location format: {target_location}")
            return None
        
        return cls.find_all_paths_in_cfg(function_name, start_line, target_line)

    @classmethod
    def trace_paths_to_exit(
        cls,
        location: str,
        eq_position: Optional[str] = None,
        *,
        arg_index: Optional[str] = None,
        callee_function_name: Optional[str] = None,
        find_current_function: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
        find_return_locations: Optional[Callable[[str], List[str]]] = None,
        find_lvalue_key_svfgnode: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None,
        find_formal_arg_key_svfgnode: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None,
        find_actual_arg_key_svfgnode: Optional[Callable[[str, str, str], List[Dict[str, Any]]]] = None,
    ) -> List[List[Dict[str, Any]]]:
        """Generates filtered paths from a start location to the function exit.
        
        Supports three analysis modes:
        - lvar: Local variable analysis (uses location and eq_position)
        - formal_arg: Formal argument analysis (uses function_name and arg_index)
        - actual_arg: Actual argument analysis (uses location, callee_function_name, and arg_index)
        
        Args:
            location: Start location 'filename:line'. For formal_arg mode, this is used to find the function.
            eq_position: Position of lvalue in the expression (for lvar mode).
            arg_index: Parameter index (for formal_arg and actual_arg modes).
            callee_function_name: Called function name (for actual_arg mode).
            find_current_function: Optional function to find current function by location.
                If None, will attempt to import from analysis_operators.
            find_return_locations: Optional function to find return locations by function name.
                If None, will attempt to import from analysis_operators.
            find_lvalue_key_svfgnode: Optional function to find key SVFG nodes for lvar mode.
                If None, will attempt to import from analysis_operators.
            find_formal_arg_key_svfgnode: Optional function to find key SVFG nodes for formal_arg mode.
                If None, will attempt to import from analysis_operators.
            find_actual_arg_key_svfgnode: Optional function to find key SVFG nodes for actual_arg mode.
                If None, will attempt to import from analysis_operators.
        
        Returns:
            List of filtered paths, containing only key value operations, branches, and start/end nodes.
        """
        # Determine analysis mode based on provided parameters
        if arg_index is not None and callee_function_name is not None:
            mode = "actual_arg"
        elif arg_index is not None:
            mode = "formal_arg"
        elif eq_position is not None:
            mode = "lvar"
        else:
            logging.error("Cannot determine analysis mode: must provide either eq_position (lvar) or arg_index (formal_arg/actual_arg)")
            return []
        
        logging.debug(f"Analysis mode: {mode}")
        
        # Resolve external dependencies
        # Determine which functions are needed based on mode
        need_lvalue = (mode == "lvar" and find_lvalue_key_svfgnode is None)
        need_formal_arg = (mode == "formal_arg" and find_formal_arg_key_svfgnode is None)
        need_actual_arg = (mode == "actual_arg" and find_actual_arg_key_svfgnode is None)
        
        if find_current_function is None or find_return_locations is None or need_lvalue or need_formal_arg or need_actual_arg:
            try:
                # Lazy import to avoid circular dependencies
                import sys
                if "analysis_operators" in sys.modules:
                    from analysis_operators import (
                        find_current_function as _find_current_function,
                        find_return_locations as _find_return_locations,
                    )
                    if find_current_function is None:
                        find_current_function = _find_current_function
                    if find_return_locations is None:
                        find_return_locations = _find_return_locations
                    
                    # Import mode-specific functions
                    if need_lvalue:
                        from analysis_operators import (
                            find_lvalue_key_svfgnode as _find_lvalue_key_svfgnode,
                        )
                        find_lvalue_key_svfgnode = _find_lvalue_key_svfgnode
                    if need_formal_arg:
                        from analysis_operators import (
                            find_formal_arg_key_svfgnode as _find_formal_arg_key_svfgnode,
                        )
                        find_formal_arg_key_svfgnode = _find_formal_arg_key_svfgnode
                    if need_actual_arg:
                        from analysis_operators import (
                            find_actual_arg_key_svfgnode as _find_actual_arg_key_svfgnode,
                        )
                        find_actual_arg_key_svfgnode = _find_actual_arg_key_svfgnode
                else:
                    # Try importing directly
                    try:
                        from analysis_operators import (
                            find_current_function as _find_current_function,
                            find_return_locations as _find_return_locations,
                        )
                        if find_current_function is None:
                            find_current_function = _find_current_function
                        if find_return_locations is None:
                            find_return_locations = _find_return_locations
                        
                        # Import mode-specific functions
                        if need_lvalue:
                            from analysis_operators import (
                                find_lvalue_key_svfgnode as _find_lvalue_key_svfgnode,
                            )
                            find_lvalue_key_svfgnode = _find_lvalue_key_svfgnode
                        if need_formal_arg:
                            from analysis_operators import (
                                find_formal_arg_key_svfgnode as _find_formal_arg_key_svfgnode,
                            )
                            find_formal_arg_key_svfgnode = _find_formal_arg_key_svfgnode
                        if need_actual_arg:
                            from analysis_operators import (
                                find_actual_arg_key_svfgnode as _find_actual_arg_key_svfgnode,
                            )
                            find_actual_arg_key_svfgnode = _find_actual_arg_key_svfgnode
                    except ImportError:
                        logging.error("Cannot import required functions from analysis_operators. Please provide them as arguments.")
                        return []
            except Exception as e:
                logging.error(f"Error resolving dependencies: {e}")
                return []
        
        if find_current_function is None or find_return_locations is None:
            logging.error("Required dependency functions (find_current_function, find_return_locations) are not available")
            return []
        
        # Check mode-specific function availability
        if mode == "lvar" and find_lvalue_key_svfgnode is None:
            logging.error("Required function find_lvalue_key_svfgnode is not available for lvar mode")
            return []
        if mode == "formal_arg" and find_formal_arg_key_svfgnode is None:
            logging.error("Required function find_formal_arg_key_svfgnode is not available for formal_arg mode")
            return []
        if mode == "actual_arg" and find_actual_arg_key_svfgnode is None:
            logging.error("Required function find_actual_arg_key_svfgnode is not available for actual_arg mode")
            return []
        
        # 1. Identify current function and determine start location
        if mode == "formal_arg":
            # For formal_arg mode, we need to find function by name
            # First, try to get function info from location to get function name
            temp_func_info = find_current_function(location)
            if not temp_func_info or "error" in temp_func_info:
                logging.error(f"Could not find function for location {location}")
                return []
            function_name = temp_func_info.get("function_name")
            
            # Get full function info to get start location
            try:
                from analysis_operators import find_function_body
                func_info = find_function_body(function_name)
            except ImportError:
                func_info = temp_func_info
            
            if not func_info or "error" in func_info:
                logging.error(f"Could not find function body for {function_name}")
                return []
            
            # Use function start line as start location for formal_arg mode
            start_line = func_info.get("start_line")
            filename = func_info.get("filename")
            if not start_line or not filename:
                logging.error(f"Could not get start_line or filename for function {function_name}")
                return []
            start_location = f"{filename}:{start_line}"
        else:
            # For lvar and actual_arg modes, use the provided location
            func_info = find_current_function(location)
            if not func_info or "error" in func_info:
                logging.error(f"Could not find function for location {location}")
                return []
            function_name = func_info.get("function_name")
            start_location = location
        
        # 2. Get target return locations
        return_locs = find_return_locations(function_name)
        if not return_locs:
            logging.warning(f"No return locations found for {function_name}")
            return []
        
        # 3. Get key value operations based on mode
        if mode == "lvar":
            key_ops = find_lvalue_key_svfgnode(location, eq_position)
        elif mode == "formal_arg":
            key_ops = find_formal_arg_key_svfgnode(function_name, arg_index)
        elif mode == "actual_arg":
            key_ops = find_actual_arg_key_svfgnode(location, callee_function_name, arg_index)
        else:
            logging.error(f"Unknown mode: {mode}")
            return []
        
        # Create a set of key locations for fast lookup
        key_locs = set()
        for op in key_ops:
            loc = op.get("location")
            if loc:
                key_locs.add(loc)
        
        logging.debug(f"Key locations: {key_locs}")
        
        # 4. Find all paths to each return location
        all_raw_paths = []
        for ret_loc in return_locs:
            paths = cls.find_all_paths_between_lines(function_name, start_location, ret_loc)
            if paths:
                all_raw_paths.extend(paths)
        
        if not all_raw_paths:
            return []

        # 5. Cluster paths by Key SVFG Node sequence (based on location)
        # We also include the return location in the key to ensure paths in a cluster end at the same place
        clusters = defaultdict(list)
        
        for path in all_raw_paths:
            if not path:
                continue
            
            # Extract sequence of key nodes (by location)
            key_seq = []
            for step in path:
                node = step.get("node", {})
                loc = node.get("location")
                edge = step.get("edge")
                
                # Key ops from backend
                if loc in key_locs:
                    key_seq.append(loc)
                # Add goto statements as key nodes
                elif edge and edge.get("type") == "goto":
                    key_seq.append(f"goto:{loc}")
            
            # Add return location to the key
            end_node = path[-1].get("node", {})
            ret_loc = end_node.get("location")
            
            # Create cluster key
            cluster_key = tuple(key_seq) + (ret_loc,)
            clusters[cluster_key].append(path)
        
        final_filtered_paths = []
        
        # 6. Process each cluster
        for cluster_key, group in clusters.items():
            if not group:
                continue
            
            base_path = group[0]
            consistent_branches = set()
            
            # Identify candidate branches from the base path
            # A branch is a node where the edge type is one of the branch types
            base_branches = []
            for step in base_path:
                edge = step.get("edge")
                if edge and edge.get("type") in ["true_branch", "false_branch", "switch_case", "loop_body", "loop_continue"]:
                    base_branches.append(step)
            
            # Check consistency against all other paths in group
            for branch_step in base_branches:
                node_id = branch_step["node"]["node_id"]
                edge_type = branch_step["edge"]["type"]
                # For switch_case, also get the condition value to distinguish different cases
                edge_condition = branch_step["edge"].get("condition") if edge_type == "switch_case" else None
                
                is_consistent = True
                for other_path in group[1:]:
                    # Find this node in other_path
                    found = False
                    for other_step in other_path:
                        if other_step["node"]["node_id"] == node_id:
                            # Check edge type
                            other_edge = other_step.get("edge")
                            if other_edge and other_edge.get("type") == edge_type:
                                # For switch_case, also check that the condition matches
                                if edge_type == "switch_case":
                                    if other_edge.get("condition") == edge_condition:
                                        found = True
                                else:
                                    found = True
                            break
                    if not found:
                        is_consistent = False
                        break
                
                if is_consistent:
                    consistent_branches.add(node_id)

            # 7. Construct Representative Path from Base Path
            filtered_path = []
            start_node = base_path[0]["node"]
            end_node = base_path[-1]["node"]

            for step in base_path:
                node = step["node"]
                node_id = node["node_id"]
                node_loc = node.get("location")
                edge = step.get("edge")
                
                keep = False
                
                # Keep Start
                if node == start_node:
                    keep = True
                # Keep Return
                elif node == end_node:
                    keep = True
                # Keep Key Nodes
                elif node_loc in key_locs:
                    keep = True
                # Keep Goto Statements
                elif edge and edge.get("type") == "goto":
                    keep = True
                # Keep Consistent Branches
                elif node_id in consistent_branches:
                    keep = True
                
                if keep:
                    filtered_path.append(step)
            
            if filtered_path:
                final_filtered_paths.append(filtered_path)
        
        return final_filtered_paths


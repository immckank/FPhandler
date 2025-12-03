import os
import json
import logging
import copy
import re
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple, Tuple
from enum import Enum

from config import *
from utils import *
from prompts import *
import analysis_operators

logger = logging.getLogger(__name__)

from openai import OpenAI


class NodeType(str, Enum):
    """预定义的节点类型"""
    Transferred = "Transferred"
    HandledByCallee = "HandledByCallee"
    Deallocated = "Deallocated"
    ReturnedAsReturnValue = "ReturnedAsReturnValue"
    ReturnedAsPointerParameter = "ReturnedAsPointerParameter"
    Leak = "Leak"
    NullPointer = "NullPointer"
    Unreachable = "Unreachable"
    
# 你正在追踪{}变量的值流来侦测可能的内存泄漏问题 
# 静态分析系统在基于当前函数内关键值流操作对路径进行了一次剪枝 识别到的路径共有{}条 每一条路径描述如下
# 1. 路径index : 1 : 这条路径上 {未发现内存转移操作 可能出现memory leak} {发现了store操作内存管理可能被转移给了函数参数或者是返回值} {发现了变量作为参数被使用可能转移给了被调用函数或已经被释放}
#   - 起始位置内存申请位置 {source_location} : {code_line}
#   - 节点类型 {branch} {source_location} : {code_line} 该条件为 {true / false}
#   - 节点类型 {store} {source_location} : {code_line} 内存很可能被存储到了函数参数 / 返回值处
#   - 节点类型 {actualparam/in} {source_location} : {code_line} 这个函数调用处变量或其别名作为参数被使用 {是一个dellocate函数 内存可能在此处被dellocate了}
#   - return 函数返回 {source_location} : {code_line}
# 2 / 3 / 4 。。。
# 你的任务是 对于每一条路径将内存状态分类为一下类型中的一个
# HandledByCallee 表示内存将会被函数调用者处理
# Deallocated 当且仅当指针被free或者用户自定义的free函数处理时
# ReturnedAsReturnValue 表示内存将会作为返回值返回 
# ReturnedAsPointerParameter 表示内存将会作为指针参数返回
# Leak 表示内存泄漏在当前函数发生了 你需要指定一个return位置 在这个return位置之后内存变量将变得unreachable
# NullPointer 表示内存将会被赋值为NULL 这往往由于内存申请失败导致 你需要指定一个return位置 表示在当前return之前 内存可能申请失败并且维持为空
# infeasible 表示该路径不可能由于条件约束等情况不可能实现

# {
    # "path_number":"4",
    # "paths":[
        # [
            # {
                # "location":"tif_dirread.c:4981","node":"start","node_desc":"IntraICFGNode62868 {fun: TIFFFetchNormalTag{ \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }}\nLoadStmt: [Var71227 <-- Var70917]\t\nValVar ID: 71227\n   %199 = load ptr, ptr %6, align 8, !dbg !12283 { \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"false","location":"tif_dirread.c:4982","node":"branch","node_desc":"IntraICFGNode62880 {fun: TIFFFetchNormalTag{ \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71237]\nSuccessor 0 ICFGNode62883   Successor 1 ICFGNode62884   \nValVar ID: 71238\n   br i1 %208, label %209, label %215, !dbg !12292 { \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:4988","node":"ActualParmVFGNode","node_desc":"ActualParmVFGNode ID: 75420 CS[CallICFGNode: { \"ln\": 4988, \"cl\": 7, \"fl\": \"tif_dirread.c\" }]ValVar ID: 71248\n   %216 = load ptr, ptr %15, align 8, !dbg !12301 { \"ln\": 4988, \"cl\": 19, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"true","location":"tif_dirread.c:4997","node":"branch","node_desc":"IntraICFGNode62838 {fun: TIFFFetchNormalTag{ \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71292]\nSuccessor 0 ICFGNode62845   Successor 1 ICFGNode62846   \nValVar ID: 71293\n   br i1 %251, label %253, label %252, !dbg !12335 { \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"false","location":"tif_dirread.c:5601","node":"branch","node_desc":"IntraICFGNode60965 {fun: TIFFFetchNormalTag{ \"ln\": 5601, \"cl\": 6, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var73309]\nSuccessor 0 ICFGNode60999   Successor 1 ICFGNode61000   \nValVar ID: 73310\n   br i1 %1782, label %1783, label %1790, !dbg !13792 { \"ln\": 5601, \"cl\": 6, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:5606","node":"return","node_desc":"IntraICFGNode61035 {fun: TIFFFetchNormalTag{ \"ln\": 5606, \"cl\": 2, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [ Unconditional branch]\nSuccessor 0 ICFGNode60829   \nValVar ID: 73321\n   br label %1791, !dbg !13801 { \"ln\": 5606, \"cl\": 2, \"fl\": \"tif_dirread.c\" }"}],[{"location":"tif_dirread.c:4981","node":"start","node_desc":"IntraICFGNode62868 {fun: TIFFFetchNormalTag{ \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }}\nLoadStmt: [Var71227 <-- Var70917]\t\nValVar ID: 71227\n   %199 = load ptr, ptr %6, align 8, !dbg !12283 { \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"false","location":"tif_dirread.c:4982","node":"branch","node_desc":"IntraICFGNode62880 {fun: TIFFFetchNormalTag{ \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71237]\nSuccessor 0 ICFGNode62883   Successor 1 ICFGNode62884   \nValVar ID: 71238\n   br i1 %208, label %209, label %215, !dbg !12292 { \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:4988","node":"ActualParmVFGNode","node_desc":"ActualParmVFGNode ID: 75420 CS[CallICFGNode: { \"ln\": 4988, \"cl\": 7, \"fl\": \"tif_dirread.c\" }]ValVar ID: 71248\n   %216 = load ptr, ptr %15, align 8, !dbg !12301 { \"ln\": 4988, \"cl\": 19, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"true","location":"tif_dirread.c:4997","node":"branch","node_desc":"IntraICFGNode62838 {fun: TIFFFetchNormalTag{ \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71292]\nSuccessor 0 ICFGNode62845   Successor 1 ICFGNode62846   \nValVar ID: 71293\n   br i1 %251, label %253, label %252, !dbg !12335 { \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"true","location":"tif_dirread.c:5601","node":"branch","node_desc":"IntraICFGNode60965 {fun: TIFFFetchNormalTag{ \"ln\": 5601, \"cl\": 6, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var73309]\nSuccessor 0 ICFGNode60999   Successor 1 ICFGNode61000   \nValVar ID: 73310\n   br i1 %1782, label %1783, label %1790, !dbg !13792 { \"ln\": 5601, \"cl\": 6, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:5604","node":"return","node_desc":"IntraICFGNode61374 {fun: TIFFFetchNormalTag{ \"ln\": 5604, \"cl\": 3, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [ Unconditional branch]\nSuccessor 0 ICFGNode60829   \nValVar ID: 73319\n   br label %1791, !dbg !13800 { \"ln\": 5604, \"cl\": 3, \"fl\": \"tif_dirread.c\" }"}],[{"location":"tif_dirread.c:4981","node":"start","node_desc":"IntraICFGNode62868 {fun: TIFFFetchNormalTag{ \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }}\nLoadStmt: [Var71227 <-- Var70917]\t\nValVar ID: 71227\n   %199 = load ptr, ptr %6, align 8, !dbg !12283 { \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"false","location":"tif_dirread.c:4982","node":"branch","node_desc":"IntraICFGNode62880 {fun: TIFFFetchNormalTag{ \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71237]\nSuccessor 0 ICFGNode62883   Successor 1 ICFGNode62884   \nValVar ID: 71238\n   br i1 %208, label %209, label %215, !dbg !12292 { \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:4988","node":"ActualParmVFGNode","node_desc":"ActualParmVFGNode ID: 75420 CS[CallICFGNode: { \"ln\": 4988, \"cl\": 7, \"fl\": \"tif_dirread.c\" }]ValVar ID: 71248\n   %216 = load ptr, ptr %15, align 8, !dbg !12301 { \"ln\": 4988, \"cl\": 19, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"false","location":"tif_dirread.c:4997","node":"branch","node_desc":"IntraICFGNode62838 {fun: TIFFFetchNormalTag{ \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71292]\nSuccessor 0 ICFGNode62845   Successor 1 ICFGNode62846   \nValVar ID: 71293\n   br i1 %251, label %253, label %252, !dbg !12335 { \"ln\": 4997, \"cl\": 10, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:4998","node":"return","node_desc":"IntraICFGNode62852 {fun: TIFFFetchNormalTag{ \"ln\": 4998, \"cl\": 7, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [ Unconditional branch]\nSuccessor 0 ICFGNode60829   \nValVar ID: 71295\n   br label %1791, !dbg !12336 { \"ln\": 4998, \"cl\": 7, \"fl\": \"tif_dirread.c\" }"}],[{"location":"tif_dirread.c:4981","node":"start","node_desc":"IntraICFGNode62868 {fun: TIFFFetchNormalTag{ \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }}\nLoadStmt: [Var71227 <-- Var70917]\t\nValVar ID: 71227\n   %199 = load ptr, ptr %6, align 8, !dbg !12283 { \"ln\": 4981, \"cl\": 30, \"fl\": \"tif_dirread.c\" }"},{"condition_value":"true","location":"tif_dirread.c:4982","node":"branch","node_desc":"IntraICFGNode62880 {fun: TIFFFetchNormalTag{ \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [Condition Var71237]\nSuccessor 0 ICFGNode62883   Successor 1 ICFGNode62884   \nValVar ID: 71238\n   br i1 %208, label %209, label %215, !dbg !12292 { \"ln\": 4982, \"cl\": 11, \"fl\": \"tif_dirread.c\" }"},{"location":"tif_dirread.c:4986","node":"return","node_desc":"IntraICFGNode62900 {fun: TIFFFetchNormalTag{ \"ln\": 4986, \"cl\": 8, \"fl\": \"tif_dirread.c\" }}\nBranchStmt: [ Unconditional branch]\nSuccessor 0 ICFGNode60829   \nValVar ID: 71247\n   br label %1791, !dbg !12300 { \"ln\": 4986, \"cl\": 8, \"fl\": \"tif_dirread.c\" }"}]]}


class FunctionPathBuilderAgent:

    def __init__(self, source_location: str, eq_position: int, client=None, model_name=None):
        self.source_location = source_location
        self.eq_position = eq_position
        self.client = client
        self.model_name = model_name
        self.path_data: List[Dict[str, Any]] = []
        self.path_number: Optional[int] = None
        self.svfg_nodes: List[Dict[str, Any]] = []  # Store SVFG nodes for path analysis
        if not self.init_function_raw_path(self.source_location, self.eq_position):
            raise ValueError(f"Failed to initialize raw path data for {self.source_location}")
        
        # 工具方法映射
        self.tool_method_map = {
            "complete_path": self.complete_path_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
            "read_ctag_symbol": self.read_ctag_symbol_Tool,
        }

    def init_function_raw_path(self, source_location: str, eq_position: int) -> bool:
        """
        初始化函数的原始路径数据。

        Args:
            source_location: 起始代码位置，格式如 'file.c:123'
            eq_position: 等式位置或额外的定位参数

        Returns:
            bool: 成功获取并保存路径数据返回 True，否则 False
        """
        self.path_data = []
        self.path_number = None

        if not isinstance(source_location, str) or not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', source_location):
            logger.error(f"[FunctionPathBuilderAgent] invalid source_location: {source_location}")
            return False

        try:
            raw_path_json = analysis_operators.get_detailed_value_sensitive_lvar_icfg_return_path(
                source_location, eq_position
            )
        except Exception as exc:
            logger.exception("[FunctionPathBuilderAgent] failed to fetch detailed path data", exc_info=exc)
            return False

        if not raw_path_json:
            logger.warning("[FunctionPathBuilderAgent] empty path data returned from analysis operator")
            return False

        paths = raw_path_json.get("paths")
        if not isinstance(paths, list):
            logger.error("[FunctionPathBuilderAgent] malformed path data: 'paths' is not a list")
            return False

        self.path_number = self._coerce_int(raw_path_json.get("path_number"))

        # Get SVFG nodes for enhanced path analysis
        try:
            self.svfg_nodes = analysis_operators.find_lvalue_key_svfgnode(
                source_location, str(eq_position)
            )
            logger.info(f"[FunctionPathBuilderAgent] Loaded {len(self.svfg_nodes)} SVFG nodes")
        except Exception as e:
            logger.warning(f"[FunctionPathBuilderAgent] Failed to fetch SVFG nodes: {e}")
            self.svfg_nodes = []

        for idx, path in enumerate(paths, start=1):
            normalized_nodes = self._normalize_nodes(path["path"])
            path_entry = {
                "path_id": f"{idx}",
                "path_classification": None,  # TODO: 后续实现内存状态分类
                "key_operation": None,        # TODO: 后续实现关键操作识别
                "path_node_list": normalized_nodes
            }
            self.path_data.append(path_entry)

        if not self.path_data:
            logger.warning("[FunctionPathBuilderAgent] no usable path data found after normalization")
            return False

        return True

    @staticmethod
    def _coerce_int(value) -> Optional[int]:
        """尝试将 path_number 转换为整数，失败则返回 None。"""
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_column_from_node_desc(node_desc: str) -> Optional[int]:
        """
        从 node_desc 字符串中提取 cl（列号）值。
        
        Args:
            node_desc: 节点描述字符串，可能包含 JSON 对象
            
        Returns:
            Optional[int]: 列号（1-based），如果提取失败返回 None
        """
        if not node_desc or not isinstance(node_desc, str):
            return None
        
        # 匹配形如 { "ln": 4995, "cl": 10, "fl": "tif_dirread.c" } 的 JSON 对象
        match = re.search(r'\{[^}]*"cl"\s*:\s*(\d+)', node_desc)
        if match:
            try:
                return int(match.group(1))
            except (ValueError, AttributeError):
                pass
        
        return None

    @staticmethod
    def _extract_branch_expression(location: str, node_desc: str, condition_value: Optional[str]) -> Optional[str]:
        """
        从分支节点中提取具体的条件表达式。
        
        Args:
            location: 代码位置，格式如 "file.c:123"
            node_desc: 节点描述字符串
            condition_value: 条件值（"true" 或 "false"）
            
        Returns:
            Optional[str]: 提取的表达式，如果提取失败返回 None
        """
        if not location or not node_desc:
            return None
        
        # 提取列号
        cl = FunctionPathBuilderAgent._extract_column_from_node_desc(node_desc)
        if cl is None:
            return None
        
        # 读取源代码行（不 strip 空白符以保持列号对齐）
        code_line = find_code_line(location, strip_whitespace=False)
        if not code_line:
            return None
        
        # 判断分支类型：cl 代表的位置如果是 for 的第一个字母 f，则为 for 循环
        # cl 是 1-based，转换为 0-based 索引需要 -1
        start_idx = cl - 1
        if start_idx < len(code_line):
            # 检查 cl 位置的字符是否为 'f'，且前后文匹配 "for"
            char_at_cl = code_line[start_idx] if start_idx < len(code_line) else ''
            # 向前查看是否是 "for" 的关键字（允许一些空白符）
            check_start = max(0, start_idx - 3)
            code_snippet = code_line[check_start:min(len(code_line), start_idx + 3)]
            is_for_loop = char_at_cl.lower() == 'f' and 'for' in code_snippet.lower()
        else:
            is_for_loop = False
        
        if is_for_loop:
            # for 循环：提取整行代码
            return code_line.strip()
        else:
            # if 分支：从 cl 位置开始，一个字符一个字符向后匹配提取表达式
            # cl 是 1-based，转换为 0-based 索引需要 -1
            start_idx = cl - 1
            
            if start_idx >= len(code_line):
                return None
            
            # 步骤1：检查前三个字符是否是 "for"
            if start_idx + 2 < len(code_line):
                first_three = code_line[start_idx:start_idx + 3].lower()
                if first_three == "for":
                    # 使用正则表达式匹配是否为for循环
                    # 检查 "for" 后面是否有括号或空格+括号
                    remaining = code_line[start_idx:].strip()
                    if re.match(r'^for\s*\(', remaining, re.IGNORECASE):
                        # 是for循环，保留整行
                        return code_line.strip()
            
            # 步骤2：如果当前表达式以 || 或 && 起始，忽略开头的 || 或 &&
            current_idx = start_idx
            while current_idx < len(code_line) - 1:
                two_chars = code_line[current_idx:current_idx + 2]
                if two_chars == '||' or two_chars == '&&':
                    current_idx += 2
                    # 跳过空白符
                    while current_idx < len(code_line) and code_line[current_idx] in [' ', '\t']:
                        current_idx += 1
                else:
                    break
            
            expr_start = current_idx
            expr_end = len(code_line)
            paren_depth = 0  # 括号深度
            
            # 步骤3：从当前位置开始，一个字符一个字符向后匹配
            i = expr_start
            while i < len(code_line):
                char = code_line[i]
                
                # 先检查是否是 || 或 &&
                if i < len(code_line) - 1:
                    two_chars = code_line[i:i+2]
                    if two_chars == '||' or two_chars == '&&':
                        # 如果深度为0，遇到 || 或 && 则停下，不包含 || 或 &&
                        if paren_depth == 0:
                            expr_end = i
                            break
                
                # 处理括号
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    # 如果深度为0时遇到 )，表明到达末尾，不包含末尾的 )
                    if paren_depth == 0:
                        expr_end = i  # 不包含这个 )
                        break
                    else:
                        paren_depth -= 1
                
                i += 1
            
            # 提取表达式
            expression = code_line[expr_start:expr_end].strip()
            return expression if expression else None

    @staticmethod
    def _handle_negation(expression: str, condition_value: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        处理逻辑取反：如果表达式以 '!' 开头且没有显式比较符号，翻转 condition_value。
        
        Args:
            expression: 提取的表达式字符串
            condition_value: 当前的条件值（"true" 或 "false"）
            
        Returns:
            tuple[str, Optional[str]]: (修正后的表达式, 翻转后的 condition_value)
        """
        if not expression or not condition_value:
            return expression, condition_value
        
        # 去除表达式开头的空白符以便检查
        expr_stripped = expression.lstrip()
        
        # 检查是否以 '!' 开头
        if not expr_stripped.startswith('!'):
            return expression, condition_value
        
        # 检查表达式中是否包含显式比较符号
        has_comparison = '==' in expression or '!=' in expression
        
        if has_comparison:
            # 如果有显式比较符号，不翻转 condition_value
            return expression, condition_value
        
        # 翻转 condition_value
        flipped_value = "false" if condition_value == "true" else "true"
        
        # 返回去掉开头的 '!' 的表达式和翻转后的值
        # 但根据用户需求，表达式保持不变，只翻转 condition_value
        return expression, flipped_value

    @staticmethod
    def _normalize_nodes(path_nodes: Any) -> List[Dict[str, Any]]:
        """
        清洗单条路径的节点列表，移除 node_desc 等冗余字段，并为 branch 节点提取表达式。

        Args:
            path_nodes: 原始节点列表

        Returns:
            List[Dict[str, Any]]: 清洗后的节点列表
        """
        if not isinstance(path_nodes, list):
            return []

        normalized: List[Dict[str, Any]] = []
        for node in path_nodes:
            if not isinstance(node, dict):
                continue
            
            # 创建新节点，移除 node_desc
            normalized_node = {k: v for k, v in node.items() if k != "node_desc"}
            
            # 如果是 branch 节点，提取表达式并处理逻辑取反
            if normalized_node.get("node") == "branch":
                node_desc = node.get("node_desc", "")
                location = normalized_node.get("location", "")
                condition_value = normalized_node.get("condition_value")
                
                # 提取表达式
                expression = FunctionPathBuilderAgent._extract_branch_expression(
                    location, node_desc, condition_value
                )
                
                if expression:
                    # 添加表达式字段
                    normalized_node["expression"] = expression
                    
                    # 处理逻辑取反
                    _, flipped_value = FunctionPathBuilderAgent._handle_negation(
                        expression, condition_value
                    )
                    if flipped_value != condition_value:
                        normalized_node["condition_value"] = flipped_value
                else:
                    # 提取失败，设置表达式为 None
                    normalized_node["expression"] = None
            
            normalized.append(normalized_node)
        return normalized

        # 源代码查询相关
    
    def dump_source_snippet_Tool(self, file_name, start_line, end_line):
        return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
    def dump_source_line_Tool(self, file_name, line_number):
        return analysis_operators.dump_source_line(file_name, line_number)
    
    def find_current_function_Tool(self, source_location):
        return analysis_operators.find_current_function(source_location)
    
    def find_function_body_Tool(self, function_name):
        return analysis_operators.find_function_body(function_name)
    
    def find_callers_Tool(self, function_name):
        return analysis_operators.find_callers(function_name)
    
    def read_ctag_symbol_Tool(self, symbol_name):
        """Look up symbol occurrences via the ctags index."""
        return analysis_operators.read_ctag_symbol(symbol_name)

    def complete_path_Tool(self, path_id: str, classification: str, reason: str,
                          key_operation_source_location: Optional[str] = None,
                          key_operation_code_line: Optional[str] = None,
                          callee_function_name: Optional[str] = None) -> Dict[str, Any]:
        """
        完成路径分类，设置路径的内存状态分类和关键操作。
        
        Args:
            path_id: 路径标识符
            classification: 路径分类，可选值：
                - HandledByCallee: 内存被调用者处理（需要key_operation和callee_function_name）
                - Deallocated: 内存被释放（需要key_operation和callee_function_name）
                - ReturnedAsReturnValue: 作为返回值返回（需要key_operation）
                - ReturnedAsPointerParameter: 作为指针参数返回（需要key_operation）
                - Leak: 内存泄漏（不需要key_operation）
                - NullPointer: 指针为空（不需要key_operation）
                - Unreachable: 路径不可达（不需要key_operation）
            reason: 分类原因说明
            key_operation_source_location: 关键操作的源代码位置（格式：file.c:line）
            key_operation_code_line: 关键操作的代码行内容
            callee_function_name: 处理/释放内存的函数名（HandledByCallee和Deallocated分类必需）
        
        Returns:
            Dict: 包含成功信息或错误信息的字典
        """
        path_id = str(path_id)
        
        # 查找路径
        path_entry = next((p for p in self.path_data if p["path_id"] == path_id), None)
        if path_entry is None:
            return {"error": f"path_id {path_id} not found"}
        
        # 检查路径是否已完成
        if path_entry["path_classification"] is not None:
            return {"error": f"path_id {path_id} is already completed with classification {path_entry['path_classification']}"}
        
        # 验证分类类型
        valid_classifications = [
            "HandledByCallee", "Deallocated", "ReturnedAsReturnValue",
            "ReturnedAsPointerParameter", "Leak", "NullPointer", "Unreachable"
        ]
        if classification not in valid_classifications:
            return {"error": f"unknown classification: {classification}. Valid types: {valid_classifications}"}
        
        # 对于需要key_operation的分类，进行验证
        requires_key_operation = classification in [
            "HandledByCallee", "Deallocated", "ReturnedAsReturnValue", "ReturnedAsPointerParameter"
        ]
        
        # 对于需要函数名的分类，进行验证
        requires_function_name = classification in ["HandledByCallee", "Deallocated"]
        
        if requires_key_operation:
            if not key_operation_source_location:
                return {"error": f"key_operation_source_location is required for classification {classification}"}
            if not key_operation_code_line:
                return {"error": f"key_operation_code_line is required for classification {classification}"}
            
            # 对于HandledByCallee和Deallocated，验证函数名
            if requires_function_name:
                if not callee_function_name:
                    return {"error": f"callee_function_name is required for classification {classification}"}
                
                # 验证函数名是否出现在key_operation_code_line中
                if callee_function_name not in key_operation_code_line:
                    return {
                        "error": f"callee_function_name '{callee_function_name}' must appear in key_operation_code_line: '{key_operation_code_line}'"
                    }
            
            # 验证source_location格式
            if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', key_operation_source_location):
                return {"error": f"invalid key_operation_source_location format: {key_operation_source_location}"}
            
            # 验证source_location必须匹配路径中某个非branch节点
            path_node_list = path_entry.get("path_node_list", [])
            matching_node = None
            for node in path_node_list:
                node_location = node.get("location")
                node_type = node.get("node", "")
                if node_location == key_operation_source_location and node_type != "branch":
                    matching_node = node
                    break
            
            if matching_node is None:
                # 列出所有非branch节点的location供参考
                non_branch_locations = [
                    n.get("location") for n in path_node_list 
                    if n.get("node") != "branch"
                ]
                return {
                    "error": f"key_operation_source_location {key_operation_source_location} does not match any non-branch node in the path. "
                             f"Available non-branch node locations: {non_branch_locations}"
                }
            
            # 验证并规范化source_location和code_line
            validation_result = analysis_operators.validate_source_location(
                key_operation_source_location, key_operation_code_line
            )
            if "error" in validation_result:
                return {"error": f"source_location validation failed: {validation_result['error']}"}
            
            validated_location = validation_result["source_location"]
            validated_code_line = validation_result.get("code_line", key_operation_code_line)
            
            # 存储关键操作信息
            key_operation_data = {
                "source_location": validated_location,
                "code_line": validated_code_line
            }
            
            # 如果提供了函数名，也存储它
            if requires_function_name and callee_function_name:
                key_operation_data["callee_function_name"] = callee_function_name
            
            path_entry["key_operation"] = key_operation_data
        else:
            # 对于不需要key_operation的分类，设置为None
            path_entry["key_operation"] = None
        
        # 设置分类和原因
        path_entry["path_classification"] = classification
        path_entry["reason"] = reason
        
        logger.info(
            f"[FunctionPathBuilderAgent] complete_path path_id={path_id} "
            f"classification={classification} key_operation={path_entry['key_operation']}"
        )
        
        return {
            "success": True,
            "path_id": path_id,
            "classification": classification,
            "reason": reason,
            "key_operation": path_entry["key_operation"]
        }

    # Core SVFG node types we care about
    _CORE_SVFG_TYPES = {
        "StoreSVFGNode": ["StoreSVFGNode", "Store"],
        "ActualParmVFGNode": ["ActualParmVFGNode", "ActualParm"],
        "ActualINSVFGNode": ["ActualINSVFGNode", "ActualIN"],
        "GepVFGNode": ["GepVFGNode", "Gep"]
    }
    
    def _is_core_svfg_type(self, svfg_node_type: str) -> Optional[str]:
        """
        Check if the SVFG node type is one of the four core types we care about.
        
        Args:
            svfg_node_type: The SVFG node type string
            
        Returns:
            The core type name if matched, None otherwise
        """
        for core_type, patterns in self._CORE_SVFG_TYPES.items():
            for pattern in patterns:
                if pattern in svfg_node_type:
                    return core_type
        return None
    
    def _match_svfg_nodes_to_path(self, path_node_list: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Match SVFG nodes to path nodes based on location.
        
        Args:
            path_node_list: List of nodes in the path
            
        Returns:
            Dictionary mapping path node locations to matching SVFG nodes
        """
        location_to_svfg = {}
        
        # Build location set from path nodes
        path_locations = set()
        for node in path_node_list:
            location = node.get("location", "")
            if location:
                path_locations.add(location)
        
        # Match SVFG nodes to path locations
        for svfg_node in self.svfg_nodes:
            svfg_location = svfg_node.get("location", "")
            if not svfg_location:
                continue
            
            # Direct match
            if svfg_location in path_locations:
                if svfg_location not in location_to_svfg:
                    location_to_svfg[svfg_location] = []
                location_to_svfg[svfg_location].append(svfg_node)
            else:
                # Try to match by file and line (ignore column)
                svfg_file_line = svfg_location.split(":")[0] + ":" + svfg_location.split(":")[1] if ":" in svfg_location else ""
                for path_loc in path_locations:
                    path_file_line = path_loc.split(":")[0] + ":" + path_loc.split(":")[1] if ":" in path_loc else ""
                    if svfg_file_line == path_file_line and svfg_file_line:
                        if path_loc not in location_to_svfg:
                            location_to_svfg[path_loc] = []
                        location_to_svfg[path_loc].append(svfg_node)
                        break
        
        return location_to_svfg
    
    def _analyze_path_with_svfg(self, path_node_list: List[Dict[str, Any]], location_to_svfg: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Analyze path using SVFG node information to detect memory operations more accurately.
        
        Args:
            path_node_list: List of nodes in the path
            location_to_svfg: Dictionary mapping locations to SVFG nodes
            
        Returns:
            Dictionary with analysis results: has_store, has_actualparam, has_actualin, has_gep, svfg_details
        """
        has_store = False
        has_actualparam = False
        has_actualin = False
        has_gep = False
        svfg_details = []  # Store SVFG node details found in this path
        
        for node in path_node_list:
            location = node.get("location", "")
            node_type = node.get("node", "")
            
            # Check if this location has matching SVFG nodes
            matching_svfgs = location_to_svfg.get(location, [])
            
            for svfg_node in matching_svfgs:
                svfg_node_type = svfg_node.get("node_type", "")
                node_desc = svfg_node.get("node_desc", "")
                
                # Analyze SVFG node types using unified method
                core_type = self._is_core_svfg_type(svfg_node_type)
                if core_type:
                    # Update corresponding flag
                    if core_type == "StoreSVFGNode":
                        has_store = True
                    elif core_type == "ActualParmVFGNode":
                        has_actualparam = True
                    elif core_type == "ActualINSVFGNode":
                        has_actualin = True
                    elif core_type == "GepVFGNode":
                        has_gep = True
                    
                    # Add to details
                    svfg_details.append({
                        "location": location,
                        "type": core_type,
                        "description": node_desc
                    })
            
            # Also check path node type as fallback (for nodes not in SVFG)
            if not matching_svfgs:
                if node_type == "store" or "Store" in node_type:
                    has_store = True
                elif "ActualParm" in node_type or "actualparam" in node_type.lower():
                    has_actualparam = True
                elif "ActualIN" in node_type or "actualin" in node_type.lower():
                    has_actualin = True
                elif "GEP" in node_type or "gep" in node_type.lower():
                    has_gep = True
        
        return {
            "has_store": has_store,
            "has_actualparam": has_actualparam,
            "has_actualin": has_actualin,
            "has_gep": has_gep,
            "svfg_details": svfg_details
        }

    def _get_svfg_description(self, svfg_node: Dict[str, Any], code_line: str) -> str:
        """
        Generate a detailed description based on SVFG node type.
        
        Args:
            svfg_node: SVFG node dictionary
            code_line: Source code line for context
            
        Returns:
            Description string for the SVFG node
        """
        svfg_type = svfg_node.get("node_type", "")
        node_desc = svfg_node.get("node_desc", "")
        
        # Generate descriptions based on SVFG node type
        if "StoreSVFGNode" in svfg_type or "Store" in svfg_type:
            # Try to extract more context from node_desc
            if "RETMU" in node_desc or "return" in node_desc.lower():
                return " (SVFG: StoreVFGNode - memory stored and may be returned via return value)"
            elif "parameter" in node_desc.lower() or "param" in node_desc.lower():
                return " (SVFG: StoreVFGNode - memory stored into function parameter)"
            else:
                return " (SVFG: StoreVFGNode - memory stored into variable/pointer)"
        
        elif "ActualParmVFGNode" in svfg_type or "ActualParm" in svfg_type:
            if "free" in code_line.lower() or "dealloc" in code_line.lower():
                return " (SVFG: ActualParmVFGNode - variable passed as argument to deallocation function)"
            else:
                # Try to extract function name from node_desc
                if "CS[CallICFGNode" in node_desc:
                    # Extract function name if possible
                    return " (SVFG: ActualParmVFGNode - variable passed as actual parameter to function call)"
                return " (SVFG: ActualParmVFGNode - variable passed as actual parameter)"
        
        elif "ActualINSVFGNode" in svfg_type or "ActualIN" in svfg_type:
            if "free" in code_line.lower() or "dealloc" in code_line.lower():
                return " (SVFG: ActualINSVFGNode - variable passed as input argument to deallocation function)"
            else:
                return " (SVFG: ActualINSVFGNode - variable passed as input argument to function call)"
        
        elif "GepVFGNode" in svfg_type or "Gep" in svfg_type:
            return " (SVFG: GepVFGNode - getelementptr operation, accessing structure member or array element)"
        
        elif "AddrVFGNode" in svfg_type or "Addr" in svfg_type:
            return " (SVFG: AddrVFGNode - address of variable is taken)"
        
        elif "FormalINSVFGNode" in svfg_type or "FormalIN" in svfg_type:
            return " (SVFG: FormalINSVFGNode - variable received as formal input parameter)"
        
        else:
            # Generic description
            return f" (SVFG: {svfg_type})"
    
    def _should_filter_node_description(self, node_type: str, location: str, 
                                        is_start_node: bool = False,
                                        core_svfg_type: Optional[str] = None,
                                        matching_svfgs: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        Check if a node's description should be filtered (not shown in detail).
        
        Base class implementation: checks if location matches key_svfg nodes.
        Subclasses can override to add additional filtering logic.
        
        Args:
            node_type: Type of the path node (e.g., "actualparam", "actualin", "start")
            location: Location string of the node (e.g., "file.c:123")
            is_start_node: Whether this is the start node of the path
            core_svfg_type: Core SVFG type if available (e.g., "ActualINSVFGNode", "ActualParmVFGNode")
            matching_svfgs: List of matching SVFG nodes for this location
            
        Returns:
            True if the node description should be filtered, False otherwise
        """
        # Check if this is an actualparam/actualin type node or a start node
        is_actual_param_type = ("ActualParm" in node_type or "actualparam" in node_type.lower() or
                               "ActualIN" in node_type or "actualin" in node_type.lower())
        
        # Also check SVFG type if available
        is_svfg_actual_param = (core_svfg_type in ("ActualParmVFGNode", "ActualINSVFGNode"))
        
        if not is_actual_param_type and not is_start_node and not is_svfg_actual_param:
            return False
        
        # Check if this location matches any key_svfg node
        if hasattr(self, 'svfg_nodes') and self.svfg_nodes:
            for svfg_node in self.svfg_nodes:
                svfg_location = svfg_node.get("location", "")
                if not svfg_location:
                    continue
                
                # Check if locations match (exact match or file:line match)
                location_matches = False
                if svfg_location == location:
                    location_matches = True
                else:
                    # Try matching by file:line (ignoring column)
                    try:
                        svfg_file_line = svfg_location.split(":")[0] + ":" + svfg_location.split(":")[1] if ":" in svfg_location else ""
                        node_file_line = location.split(":")[0] + ":" + location.split(":")[1] if ":" in location else ""
                        if svfg_file_line and svfg_file_line == node_file_line:
                            location_matches = True
                    except Exception:
                        pass
                
                if location_matches:
                    # Check if SVFG node type matches actualparam/actualin
                    svfg_node_type = svfg_node.get("node_type", "")
                    core_type = self._is_core_svfg_type(svfg_node_type)
                    if core_type in ("ActualParmVFGNode", "ActualINSVFGNode"):
                        # If this is a start node or actualparam/actualin type, filter it
                        if is_actual_param_type or is_svfg_actual_param or (is_start_node and core_type in ("ActualParmVFGNode", "ActualINSVFGNode")):
                            return True
        
        return False

    def build_prompt(self) -> str:
        """
        Build an English prompt describing all pruned paths and memory events.
        """
        var_name = self._infer_variable_name()
        path_count = self.path_number or len(self.path_data)
        current_function_info = self.find_current_function_Tool(self.source_location)
        
        prompt_parts = [
            f"You are tracing the value flow of variable '{var_name}' to detect potential memory leaks. start from the location: {self.source_location} : {find_code_line(self.source_location)}",
            f"The static analysis engine pruned the control-flow in function {current_function_info['function_name']} and identified {path_count} candidate paths. Each path is described below."
        ]

        for idx, path_entry in enumerate(self.path_data, start=1):
            path_id = path_entry["path_id"]
            path_node_list = path_entry.get("path_node_list", [])
            
            # Match SVFG nodes to this path
            location_to_svfg = self._match_svfg_nodes_to_path(path_node_list)
            
            # Analyze path features using SVFG information
            path_analysis = self._analyze_path_with_svfg(path_node_list, location_to_svfg)
            has_store = path_analysis["has_store"]
            has_actualparam = path_analysis["has_actualparam"]
            has_actualin = path_analysis["has_actualin"]
            has_gep = path_analysis["has_gep"]
            svfg_details = path_analysis["svfg_details"]
            
            # Create a mapping from location to core SVFG type for quick lookup
            location_to_core_svfg_type = {}
            for detail in svfg_details:
                loc = detail["location"]
                if loc not in location_to_core_svfg_type:
                    location_to_core_svfg_type[loc] = detail["type"]
            
            path_observations = []
            path_details = []
            
            for node in path_node_list:
                node_type = node.get("node", "")
                location = node.get("location", "")
                condition_value = node.get("condition_value")
                
                code_line = find_code_line(location) if location else ""
                if not code_line:
                    code_line = location  # Fallback
                
                # Get SVFG information for this location (already analyzed)
                matching_svfgs = location_to_svfg.get(location, [])
                core_svfg_type = location_to_core_svfg_type.get(location)
                
                # Get SVFG description if available
                svfg_info = ""
                if matching_svfgs and core_svfg_type:
                    # Find the matching SVFG node of the core type
                    for svfg in matching_svfgs:
                        if self._is_core_svfg_type(svfg.get("node_type", "")) == core_svfg_type:
                            svfg_info = self._get_svfg_description(svfg, code_line)
                            break
                elif matching_svfgs:
                    # Use first matching SVFG node if no core type matched
                    svfg_info = self._get_svfg_description(matching_svfgs[0], code_line)
                
                # Check if this node description should be filtered
                # Pass SVFG information to help with filtering
                should_filter = self._should_filter_node_description(
                    node_type, location, 
                    is_start_node=(node_type == "start"),
                    core_svfg_type=core_svfg_type,
                    matching_svfgs=matching_svfgs
                )
                
                if node_type == "start":
                    path_details.append(f"  - Allocation start at {location} : {code_line}")
                elif node_type == "branch":
                    cond_str = condition_value if condition_value not in (None, "") else "unknown"
                    expression = node.get("expression")
                    if expression:
                        path_details.append(f"  - Node type branch {location} : condition \"{expression}\" evaluated to {cond_str}")
                    else:
                        path_details.append(f"  - Node type branch {location} : {code_line} (condition evaluated to {cond_str})")
                elif node_type == "store" or "Store" in node_type:
                    base_desc = f"  - Node type {node_type} {location} : {code_line} (memory likely stored into parameters/return value)"
                    # Only append svfg_info if not filtered
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif "ActualParm" in node_type or "actualparam" in node_type.lower():
                    if "free" in code_line.lower() or "dealloc" in code_line.lower():
                        base_desc = f"  - Node type {node_type} {location} : {code_line} (variable used as argument of a deallocation function)"
                    else:
                        base_desc = f"  - Node type {node_type} {location} : {code_line} (variable or alias used as call argument)"
                    # Only append svfg_info if not filtered
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif "ActualIN" in node_type or "actualin" in node_type.lower():
                    base_desc = f"  - Node type {node_type} {location} : {code_line}"
                    # Only append svfg_info if not filtered
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
                elif node_type == "return":
                    path_details.append(f"  - return statement {location} : {code_line}")
                else:
                    # For other node types (including "normal"), always show the basic description
                    # but only append SVFG info if not filtered
                    base_desc = f"  - Node type {node_type} {location} : {code_line}"
                    path_details.append(base_desc + (svfg_info if not should_filter else ""))
            
            # 构建路径观察描述 - 使用SVFG信息进行更准确的判断
            if has_store:
                path_observations.append("store operations detected; ownership may be passed to parameters or return values")
            if has_actualparam:
                path_observations.append("variable is used as a call argument; ownership may transfer to the callee or be freed there")
            if has_actualin:
                path_observations.append("variable passed as input argument; may be used by callee function")
            if has_gep:
                path_observations.append("pointer arithmetic/field access detected; memory may be accessed through structure or array")
            
            # Only add "no memory transfer" if none of the transfer operations were detected
            if not (has_store or has_actualparam or has_actualin):
                path_observations.append("no memory transfer detected; potential leak at return")
            
            observations_str = " ".join(path_observations) if path_observations else "no noteworthy memory events"
            
            prompt_parts.append(f"{idx}. path_id: {idx}: {observations_str}")
            prompt_parts.extend(path_details)
            
            # # Add detailed SVFG information if available for this path
            # if svfg_details:
            #     prompt_parts.append("    SVFG nodes in this path:")
            #     for svfg_detail in svfg_details:
            #         svfg_loc = svfg_detail["location"]
            #         svfg_type = svfg_detail["type"]
            #         svfg_desc = svfg_detail["description"]
            #         # Clean up description
            #         cleaned_desc = " ".join(svfg_desc.split())[:150] if svfg_desc else ""
            #         if len(svfg_desc) > 150:
            #             cleaned_desc += "..."
            #         prompt_parts.append(f"      - {svfg_type} at {svfg_loc}: {cleaned_desc}")

        prompt_parts.extend([
            "",
            " Your task is to classify each path into one of the following memory states:",
            "- HandledByCallee: memory will be handled by a callee function.",
            "- Deallocated: memory is explicitly freed (e.g., free or custom free).",
            "- ReturnedAsReturnValue: memory is returned via the function's return value.",
            "- ReturnedAsPointerParameter: memory is returned through a pointer parameter.",
            "- Leak: memory is leaked at this return location.",
            "- NullPointer: the pointer remains NULL due to allocation failures.",
            "- Unreachable: the path is infeasible due to control-flow constraints.",
            "",
            "For each path, you must first check if the path is feasible. If the path is not feasible, you should classify it as Unreachable directly.",
        ])

        return "\n".join(prompt_parts)

    def _infer_variable_name(self) -> str:
        """
        Infer the tracked variable name using the start source line.
        """
        try:
            code_line = find_code_line(self.source_location)
            if code_line:
                var_name = extract_lhs_variable(code_line)
                if var_name:
                    return var_name
        except Exception:
            pass
        return "unknown"

    def send_message(self, messages, tools=""):
        """Send message to LLM and return response."""
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        tool_count = len(tools) if isinstance(tools, (list, tuple)) else (len(tools) if tools else 0)
        print(
            "[FunctionPathBuilderAgent] send_message model=%s messages=%d tools=%d"
            % (self.model_name, len(messages), tool_count)
        )
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        print(
            "[FunctionPathBuilderAgent] response content=%s"
            % (response.choices[0].message.content if response.choices[0].message else None)
        )
        print(
            "[FunctionPathBuilderAgent] received response has_content=%s tool_calls=%d"
            % (
                bool(response.choices[0].message.content),
                len(response.choices[0].message.tool_calls or []),
            )
        )
        return response.choices[0].message

    def handle_agent_tool_call(self, tool_call):
        """Handle agent tool call."""
        function_name = "unknown"
        try:
            function_obj = getattr(tool_call, "function", tool_call)
            function_name = getattr(function_obj, "name", None)
            if not function_name:
                raise ValueError("missing function name in tool call")
            
            raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
            tool_arguments = safe_load_json(raw_arguments)
            
            print("[FunctionPathBuilderAgent] tool_call name=%s arguments=%s" % (function_name, raw_arguments))
            
            handler = self.tool_method_map.get(function_name)
            if handler is None:
                return {"error": f"unknown tool function: {function_name}"}
            
            if isinstance(tool_arguments, dict):
                result = handler(**tool_arguments)
            elif isinstance(tool_arguments, list):
                result = handler(*tool_arguments)
            else:
                result = handler(tool_arguments)
            
            print("[FunctionPathBuilderAgent] tool_call result=%s" % (result))
            return result
        except Exception as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}

    def check_path_completeness(self):
        """Check which paths are not yet completed."""
        incomplete_paths = []
        for path_entry in self.path_data:
            if path_entry.get("path_classification") is None:
                incomplete_paths.append(path_entry["path_id"])
        return incomplete_paths

    def _get_allowed_tools(self):
        """Get list of allowed tools."""
        from tools import (
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            read_ctag_symbol_desc_free,
            complete_path_desc_function_path_builder
        )
        return [
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            read_ctag_symbol_desc_free,
            complete_path_desc_function_path_builder
        ]
    
    def _group_paths(self):
        # 在分析完成之后我们可以再对路径进行一次聚类 某些路径是因为我们多判定了关键值流节点才导致冗余的
        '''
        
        '''
        # 聚类算法 
        # 
        return None

    def analyze_paths(self):
        """
        Main analysis loop: interact with LLM until all paths are classified.
        
        Returns:
            List[Dict]: List of completed path entries
        """
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        # Build initial prompt
        prompt = self.build_prompt()
        print("[FunctionPathBuilderAgent] user_prompt=\n%s" % prompt)
        # return None
        
        # Build system prompt (using VALUE_PATH_PROMPT as base)
        system_prompt = VALUE_PATH_PROMPT + "\n" + ASSUMPTION_PROMPT
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        logger
        
        allowed_tools = self._get_allowed_tools()
        response = self.send_message(messages, allowed_tools)
        
        if not response.content:
            response.content = ""
        messages.append(response)
        
        # Main loop: continue until all paths are completed
        while True:
            if not response.tool_calls:
                # Check if all paths are completed
                incomplete_paths = self.check_path_completeness()
                if len(incomplete_paths) == 0:
                    break
                
                # Prompt to complete remaining paths
                messages.append({
                    "role": "user",
                    "content": (
                        f"The following paths are not yet completed: {incomplete_paths}. "
                        "Please complete these paths by classifying their memory state using the complete_path tool."
                    )
                })
                response = self.send_message(messages, allowed_tools)
                if not response.content:
                    response.content = ""
                messages.append(response)
                continue
            
            # Process each tool call
            for tool_call in response.tool_calls:
                function_response = self.handle_agent_tool_call(tool_call)
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response, ensure_ascii=False)
                print("[FunctionPathBuilderAgent] function_response=%s" % (function_response))
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "content": function_response
                })
            
            # Get next response
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            messages.append(response)
        
        # Return all completed paths
        return [path_entry for path_entry in self.path_data if path_entry.get("path_classification") is not None]

class FunctionPathCheckerAgent:
    """
    路径可达性检查Agent
    
    功能：
    1. 验证完整路径是否可达（从起始位置到return位置）
    2. 检查路径上的所有分支条件约束是否存在冲突
    3. 分类路径为 feasible 或 not feasible
    """
    
    def __init__(self, path_data: List[Dict[str, Any]], client=None, model_name=None):
        """
        初始化路径检查Agent
        
        Args:
            path_data: 从 FunctionPathBuilderAgent 获取的已分类路径数据列表
            client: LLM 客户端（OpenAI client）
            model_name: 使用的模型名称
        """
        self.path_data = path_data
        self.client = client
        self.model_name = model_name
        
        # 工具方法映射
        self.tool_method_map = {
            "check_path": self.check_path_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
        }
    
    # 源代码查询相关工具
    
    def dump_source_snippet_Tool(self, file_name, start_line, end_line):
        """获取源代码片段"""
        return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
    def dump_source_line_Tool(self, file_name, line_number):
        """获取单行源代码"""
        return analysis_operators.dump_source_line(file_name, line_number)
    
    def find_current_function_Tool(self, source_location):
        """查找源位置所在的函数"""
        return analysis_operators.find_current_function(source_location)
    
    def find_function_body_Tool(self, function_name):
        """查找函数体"""
        return analysis_operators.find_function_body(function_name)
    
    def find_callers_Tool(self, function_name):
        """查找函数的调用者"""
        return analysis_operators.find_callers(function_name)
    
    def check_path_Tool(self, path_id: str, feasibility: str, reason: str) -> Dict[str, Any]:
        """
        标记路径的可达性分类
        
        Args:
            path_id: 路径标识符
            feasibility: 可达性分类，必须是 "feasible" 或 "not feasible"
            reason: 分类原因说明，包括约束冲突分析
        
        Returns:
            Dict: 包含成功信息或错误信息的字典
        """
        path_id = str(path_id)
        
        # 查找路径
        path_entry = next((p for p in self.path_data if p["path_id"] == path_id), None)
        if path_entry is None:
            return {"error": f"path_id {path_id} not found"}
        
        # 检查路径是否已检查
        if path_entry.get("feasibility") is not None:
            return {"error": f"path_id {path_id} is already checked with feasibility {path_entry['feasibility']}"}
        
        # 验证可达性分类
        valid_feasibilities = ["feasible", "not feasible"]
        if feasibility not in valid_feasibilities:
            return {"error": f"unknown feasibility: {feasibility}. Valid values: {valid_feasibilities}"}
        
        # 设置可达性和原因
        path_entry["feasibility"] = feasibility
        path_entry["feasibility_reason"] = reason
        
        logger.info(
            f"[FunctionPathCheckerAgent] check_path path_id={path_id} "
            f"feasibility={feasibility}"
        )
        
        return {
            "success": True,
            "path_id": path_id,
            "feasibility": feasibility,
            "reason": reason
        }
    
    def build_prompt(self) -> str:
        """
        构建英文提示，描述所有路径的约束条件，强调路径可达性和约束冲突分析
        """
        path_count = len(self.path_data)
        loop_pattern = re.compile(r"^\s*(for|while)\s*\(")

        def format_branch_condition(expression: str, value: Any) -> str:
            """
            将条件转换为 assume 形式，value 为真表示直接假设表达式成立，
            否则假设其否定成立。无法判断时默认 assume(expr)。
            """
            expr_text = expression or "<unknown condition>"
            normalized = None
            if isinstance(value, bool):
                normalized = value
            elif isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "1", "yes"}:
                    normalized = True
                elif lowered in {"false", "0", "no"}:
                    normalized = False
            if normalized is True:
                if loop_pattern.match(expr_text):
                    return f"assume(loop iteration continues: {expr_text})"
                return f"assume({expr_text})"
            if normalized is False:
                if loop_pattern.match(expr_text):
                    return f"assume(after loop: {expr_text})"
                return f"assume(¬({expr_text}))"
            if loop_pattern.match(expr_text):
                return f"assume(loop branch: {expr_text})"
            return f"assume({expr_text})"
        
        prompt_parts = [
            f"You are analyzing the feasibility of {path_count} execution paths from a static analysis.",
            "Each path contains a sequence of branch conditions that must be satisfied for the path to be executable.",
            "Your task is to check whether each path is feasible by analyzing the branch constraints.",
            "The branch conditions for each path are canonicalized constraints derived after clustering many concrete executions; they represent the shared assumptions for that path cluster.",
            "Consider a path feasible if there exists at least one real execution that can simultaneously satisfy all listed constraints.",
            ""
        ]
        
        for idx, path_entry in enumerate(self.path_data, start=1):
            path_id = path_entry["path_id"]
            path_classification = path_entry.get("path_classification", "Unknown")
            path_node_list = path_entry.get("path_node_list", [])
            
            # 提取路径的起始和结束位置
            start_node = None
            end_node = None
            branch_conditions = []
            
            for node in path_node_list:
                node_type = node.get("node", "")
                location = node.get("location", "")
                
                if node_type == "start":
                    start_node = location
                    code_line = find_code_line(location) if location else ""
                    if code_line:
                        start_node = f"{location} : {code_line}"
                
                if node_type == "return":
                    end_node = location
                    code_line = find_code_line(location) if location else ""
                    if code_line:
                        end_node = f"{location} : {code_line}"
                
                if node_type == "branch":
                    condition_value = node.get("condition_value")
                    expression = node.get("expression")
                    code_line = find_code_line(location) if location else ""
                    
                    if expression:
                        branch_conditions.append({
                            "location": location,
                            "expression": expression,
                            "value": condition_value,
                            "code_line": code_line
                        })
                    elif code_line:
                        branch_conditions.append({
                            "location": location,
                            "expression": code_line,
                            "value": condition_value,
                            "code_line": code_line
                        })
            
            # 构建路径描述
            prompt_parts.append(f"Path {idx} (path_id: {path_id}):")
            # prompt_parts.append(f"  Classification: {path_classification}")
            
            if start_node:
                prompt_parts.append(f"  Start: {start_node}")
            
            # 列出所有分支条件
            if branch_conditions:
                for i, cond in enumerate(branch_conditions, start=1):
                    cond_str = format_branch_condition(cond["expression"], cond["value"])
                    prompt_parts.append(f"  Branch {i}: {cond['location']}: {cond_str}")
            else:
                prompt_parts.append("  No branch constraints (direct path)")

            if end_node:
                prompt_parts.append(f"  End: {end_node}")
            
            prompt_parts.append("")
        
        prompt_parts.extend([
            "",
            "Your task:",
            "1. For each path, analyze whether the branch constraints are consistent and the path is executable.",
            "2. Check for conflicting constraints (e.g., 'x > 0' followed by 'x == 0').",
            "3. Consider the context and semantics of the conditions.",
            "4. Classify each path as 'feasible' (the path can be executed) or 'not feasible' (the path has conflicting constraints or is unreachable).",
            "5. Provide a clear explanation of your reasoning, especially highlighting any constraint conflicts.",
            "",
            "Use the check_path tool to mark each path's feasibility.",
            "You may use the source code query tools (dump_source_snippet, dump_source_line, etc.) to gather more context if needed."
        ])
        
        return "\n".join(prompt_parts)
    
    def send_message(self, messages, tools=""):
        """发送消息到LLM并返回响应"""
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        tool_count = len(tools) if isinstance(tools, (list, tuple)) else (len(tools) if tools else 0)
        print(
            "[FunctionPathCheckerAgent] send_message model=%s messages=%d tools=%d"
            % (self.model_name, len(messages), tool_count)
        )
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        print(
            "[FunctionPathCheckerAgent] response content=%s"
            % (response.choices[0].message.content if response.choices[0].message else None)
        )
        print(
            "[FunctionPathCheckerAgent] received response has_content=%s tool_calls=%d"
            % (
                bool(response.choices[0].message.content),
                len(response.choices[0].message.tool_calls or []),
            )
        )
        return response.choices[0].message
    
    def handle_agent_tool_call(self, tool_call):
        """处理Agent的工具调用"""
        function_name = "unknown"
        try:
            function_obj = getattr(tool_call, "function", tool_call)
            function_name = getattr(function_obj, "name", None)
            if not function_name:
                raise ValueError("missing function name in tool call")
            
            raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
            tool_arguments = safe_load_json(raw_arguments)
            
            print("[FunctionPathCheckerAgent] tool_call name=%s arguments=%s" % (function_name, raw_arguments))
            
            handler = self.tool_method_map.get(function_name)
            if handler is None:
                return {"error": f"unknown tool function: {function_name}"}
            
            if isinstance(tool_arguments, dict):
                result = handler(**tool_arguments)
            elif isinstance(tool_arguments, list):
                result = handler(*tool_arguments)
            else:
                result = handler(tool_arguments)
            
            print("[FunctionPathCheckerAgent] tool_call result=%s" % (result))
            return result
        except Exception as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}
    
    def check_path_completeness(self):
        """检查哪些路径尚未完成可达性检查"""
        incomplete_paths = []
        for path_entry in self.path_data:
            if path_entry.get("feasibility") is None:
                incomplete_paths.append(path_entry["path_id"])
        return incomplete_paths
    
    def _get_allowed_tools(self):
        """获取允许使用的工具列表"""
        from tools import (
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            check_path_desc_function_path_checker
        )
        return [
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            check_path_desc_function_path_checker
        ]
    
    def analyze_paths(self):
        """
        主分析循环：与LLM交互直到所有路径都被分类为可达或不可达
        
        Returns:
            List[Dict]: 已完成可达性检查的路径列表
        """
        if not self.client:
            raise ValueError("LLM client not provided")
        if not self.model_name:
            raise ValueError("LLM model_name not provided")
        
        # 构建初始提示
        prompt = self.build_prompt()
        print("[FunctionPathCheckerAgent] user_prompt=\n%s" % prompt)
        
        # 构建系统提示
        system_prompt = VALUE_PATH_PROMPT + "\n" + ASSUMPTION_PROMPT
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        allowed_tools = self._get_allowed_tools()
        response = self.send_message(messages, allowed_tools)
        
        if not response.content:
            response.content = ""
        messages.append(response)
        
        # 主循环：继续直到所有路径都被检查
        while True:
            if not response.tool_calls:
                # 检查是否所有路径都已完成
                incomplete_paths = self.check_path_completeness()
                if len(incomplete_paths) == 0:
                    break
                
                # 提示完成剩余路径
                messages.append({
                    "role": "user",
                    "content": (
                        f"The following paths have not been checked yet: {incomplete_paths}. "
                        "Please check these paths by analyzing their constraint feasibility using the check_path tool."
                    )
                })
                response = self.send_message(messages, allowed_tools)
                if not response.content:
                    response.content = ""
                messages.append(response)
                continue
            
            # 处理每个工具调用
            for tool_call in response.tool_calls:
                function_response = self.handle_agent_tool_call(tool_call)
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response, ensure_ascii=False)
                print("[FunctionPathCheckerAgent] function_response=%s" % (function_response))
                messages.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "content": function_response
                })
            
            # 获取下一个响应
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            messages.append(response)
        
        # 返回所有已完成检查的路径
        return [path_entry for path_entry in self.path_data if path_entry.get("feasibility") is not None]
    
class FunctionSummaryAgent:
    # 这个agent主要是用来总结路径中经过的 不关键的函数
    # 获取一个不重要的函数的函数名
    # 
     
    def __init__(self, function_name: str):
        pass

# class FunctionPathBuilderAgent:
#     """函数路径构建Agent - 完全独立实现，不依赖现有系统"""
    
#     _node_counter = defaultdict(int)
#     _edge_counter = defaultdict(int)
#     _path_counter = defaultdict(int)
    
#     @classmethod
#     def allocate_node_id(cls, path_id: str):
#         cls._node_counter[path_id] += 1
#         return f"{path_id}_node_{cls._node_counter[path_id]}"
    
#     @classmethod
#     def allocate_edge_id(cls, path_id: str):
#         cls._edge_counter[path_id] += 1
#         return f"{path_id}_edge_{cls._edge_counter[path_id]}"
    
#     @classmethod
#     def allocate_path_id(cls, function_name: str):
#         cls._path_counter[function_name] += 1
#         return f"{function_name}_path_{cls._path_counter[function_name]}"
    
#     def __init__(self, current_function_info: Dict[str, Any], var_info: Dict[str, Any],
#                  start_location: str, client=None, model_name=None):
#         """
#         初始化FunctionPathBuilderAgent
        
#         Args:
#             current_function_info: 当前函数信息
#             var_info: 变量信息，包含var_name, var_type, arg_index, gep_info等
#             start_location: 起始位置
#             client: LLM客户端
#             model_name: 模型名称
#         """
#         self.analysis_logger = setup_logger(log_type="analysis")
#         self.current_function_info = current_function_info
#         self.var_info = var_info
#         self.start_location = start_location
#         self.client = client
#         self.model_name = model_name
        
#         # 路径列表
#         self.paths: Dict[str, Path] = {}
#         self.return_location_list = []
#         self.custom_node_types: Dict[str, str] = {}  # type_name -> description
#         self.path_build_queue: List[str] = []
#         self.path_index_map: Dict[str, int] = {}
#         self.path_to_return_location_map: Dict[str, Dict[str, Any]] = {}
#         self.active_path_pointer = 0
#         self.active_path_id: Optional[str] = None
        
#         # 工具方法映射
#         self.tool_method_map = {
#             "add_state_node": self.add_state_node_Tool,
#             "add_transition_edge": self.add_transition_edge_Tool,
#             "complete_path": self.complete_path_Tool,
#             "create_custom_node_type": self.create_custom_node_type_Tool,
#             "dump_source_snippet": self.dump_source_snippet_Tool,
#             "dump_source_line": self.dump_source_line_Tool,
#             "find_current_function": self.find_current_function_Tool,
#             "find_function_body": self.find_function_body_Tool,
#             "find_callers": self.find_callers_Tool,
#         }
#         print(f"[FunctionPathBuilderAgent] init function={current_function_info.get('function_name')} "
#                    f"var={var_info.get('var_name')} start={start_location}")
#         logger.info(f"[FunctionPathBuilderAgent] init function={current_function_info.get('function_name')} "
#                    f"var={var_info.get('var_name')} start={start_location}")
    
#     def send_message(self, messages, tools=""):
#         """发送消息到LLM"""
#         tool_count = len(tools) if isinstance(tools, (list, tuple)) else (len(tools) if tools else 0)
#         logger.info(f"[FunctionPathBuilderAgent] send_message model={self.model_name} "
#                    f"messages={len(messages)} tools={tool_count}")
        
#         if not self.client:
#             raise ValueError("LLM client not provided")
        
#         response = self.client.chat.completions.create(
#             model=self.model_name,
#             messages=messages,
#             tools=tools
#         )
#         response_message = response.choices[0].message
#         tool_calls = getattr(response_message, "tool_calls", None) or []
#         self._log_model_response(response_message, tool_calls)
#         return response_message

#     def _log_model_response(self, response_message, tool_calls):
#         """记录模型返回内容"""
#         if response_message is None:
#             logger.debug("[FunctionPathBuilderAgent] model_response: <empty response>")
#             return
#         content = getattr(response_message, "content", "") or ""
#         if content and len(content) > 400:
#             content = content[:400] + "...(truncated)"
#         logger.debug(f"[FunctionPathBuilderAgent] model_response: content={content or '<no content>'} "
#                      f"tool_calls={len(tool_calls)}")
#         print(f"[FunctionPathBuilderAgent] model_response: content={content or '<no content>'} "
#                      f"tool_calls={len(tool_calls)}")
    
#     def handle_agent_tool_call(self, tool_call):
#         """处理agent的工具调用"""
#         try:
#             function_obj = getattr(tool_call, "function", tool_call)
#             function_name = getattr(function_obj, "name", None)
#             if not function_name:
#                 raise ValueError("missing function name in tool call")
            
#             raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
#             tool_arguments = safe_load_json(raw_arguments)
            
#             logger.info(f"[FunctionPathBuilderAgent] tool_call name={function_name} arguments={raw_arguments}")
            
#             handler = self.tool_method_map.get(function_name)
#             if handler is None:
#                 return {"error": f"unknown tool function: {function_name}"}
            
#             if isinstance(tool_arguments, dict):
#                 result = handler(**tool_arguments)
#             elif isinstance(tool_arguments, list):
#                 result = handler(*tool_arguments)
#             else:
#                 result = handler(tool_arguments)
#             print(f"[FunctionPathBuilderAgent] tool_call result={result}")
#             return result
#         except Exception as e:
#             return {"error": f"failed to execute tool {function_name}: {str(e)}"}
    
#     # 源代码查询工具
#     def dump_source_snippet_Tool(self, file_name, start_line, end_line):
#         return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
#     def dump_source_line_Tool(self, file_name, line_number):
#         return analysis_operators.dump_source_line(file_name, line_number)
    
#     def find_current_function_Tool(self, source_location):
#         return analysis_operators.find_current_function(source_location)
    
#     def find_function_body_Tool(self, function_name):
#         return analysis_operators.find_function_body(function_name)
    
#     def find_callers_Tool(self, function_name):
#         return analysis_operators.find_callers(function_name)
    
#     # 路径构建工具
#     def add_state_node_Tool(self, node_type: str, location: str, code_line: str,
#                            source_object: Optional[str] = None, target_object: Optional[str] = None,
#                            metadata: Optional[Dict[str, Any]] = None):
#         """添加状态节点到路径"""
#         path_id = self._ensure_active_path_id()
#         if not path_id:
#             return {"error": "no active path available"}
        
#         path = self.paths[path_id]
        
#         # 验证节点类型（允许Initial作为起始节点类型）
#         valid_types = [e.value for e in NodeType] + list(self.custom_node_types.keys()) + ["Initial"]
#         if node_type not in valid_types:
#             return {"error": f"unknown node_type: {node_type}. Valid types: {valid_types}"}
        
#         # 验证location格式
#         if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', location):
#             return {"error": f"invalid location format: {location}"}
        
#         node_id = self.allocate_node_id(path_id)
#         node = StateNode(node_id, node_type, location, code_line, source_object, target_object, metadata)
#         path.add_node(node)
        
#         logger.info(f"[FunctionPathBuilderAgent] add_state_node path_id={path_id} node_id={node_id} node_type={node_type}")
#         return {"node_id": node_id, "path_id": path_id, "node": node.to_dict()}
    
#     def add_transition_edge_Tool(self, from_node_id: str, to_node_id: str,
#                                 conditions: str, location: str, code_line: str, description: str):
#         """添加转换边到路径"""
#         path_id = self._ensure_active_path_id()
#         if not path_id:
#             return {"error": "no active path available"}
        
#         path = self.paths[path_id]
        
#         # 验证节点是否存在
#         from_node = next((n for n in path.nodes if n.node_id == from_node_id), None)
#         to_node = next((n for n in path.nodes if n.node_id == to_node_id), None)
        
#         if not from_node:
#             return {"error": f"from_node_id {from_node_id} not found in path {path_id}"}
#         if not to_node:
#             return {"error": f"to_node_id {to_node_id} not found in path {path_id}"}
        
#         # 验证节点顺序（to_node应该在from_node之后）
#         from_idx = next((i for i, n in enumerate(path.nodes) if n.node_id == from_node_id), -1)
#         to_idx = next((i for i, n in enumerate(path.nodes) if n.node_id == to_node_id), -1)
        
#         if from_idx >= to_idx:
#             return {"error": f"invalid node order: from_node must come before to_node"}
        
#         # 验证location格式
#         if not re.match(r'^[\w/]+\.(c|h|cpp):\d+$', location):
#             return {"error": f"invalid location format: {location}"}
        
#         edge_id = self.allocate_edge_id(path_id)
#         edge = TransitionEdge(edge_id, from_node_id, to_node_id, conditions, location, code_line, description)
#         path.add_edge(edge)
        
#         logger.info(f"[FunctionPathBuilderAgent] add_transition_edge path_id={path_id} edge_id={edge_id} "
#                    f"from={from_node_id} to={to_node_id}")
#         return {"edge_id": edge_id, "path_id": path_id, "edge": edge.to_dict()}
    
#     def complete_path_Tool(self, termination_type: str, reason: str):
#         """完成路径，指定终止状态"""
#         path_id = self._ensure_active_path_id()
#         if not path_id:
#             return {"error": "no active path available"}
        
#         path = self.paths[path_id]
        
#         # 验证终止类型
#         valid_termination_types = [
#             "Deallocated", "Leak", "ReturnedAsReturnValue",
#             "ReturnedAsPointerParameter", "NullPointer", "Unreachable"
#         ]
#         if termination_type not in valid_termination_types:
#             return {"error": f"invalid termination_type: {termination_type}. "
#                            f"Must be one of {valid_termination_types}"}
        
#         # 验证路径
#         validation_result = self.validate_path(path_id)
#         if "error" in validation_result:
#             return validation_result
        
#         path.status = "completed"
#         path.termination_type = termination_type
#         path.termination_reason = reason
#         self._increment_completed_count(path_id)
        
#         current_index = self.path_index_map.get(path_id)
#         if current_index is not None and current_index >= self.active_path_pointer:
#             self.active_path_pointer = current_index + 1
#         elif current_index is None:
#             self.active_path_pointer += 1
#         self.active_path_id = None
#         self._set_next_active_path()
        
#         logger.info(f"[FunctionPathBuilderAgent] complete_path path_id={path_id} termination_type={termination_type}")
#         return {"path_id": path_id, "status": "completed", "path": path.to_dict()}
    
#     def create_custom_node_type_Tool(self, type_name: str, description: str):
#         """创建自定义节点类型"""
#         if type_name in [e.value for e in NodeType]:
#             return {"error": f"type_name {type_name} is already a predefined node type"}
        
#         if type_name in self.custom_node_types:
#             return {"error": f"type_name {type_name} already exists"}
        
#         self.custom_node_types[type_name] = description
#         logger.info(f"[FunctionPathBuilderAgent] create_custom_node_type type_name={type_name}")
#         return {"type_name": type_name, "description": description}
    
#     def query_path_Tool(self, path_id: str):
#         """查询路径的当前状态"""
#         if path_id not in self.paths:
#             return {"error": f"path_id {path_id} not found"}
        
#         path = self.paths[path_id]
#         return path.to_dict()
    
#     def merge_paths_Tool(self, path_ids: List[str], description: str = ""):
#         """合并多条相似路径"""
#         if len(path_ids) < 2:
#             return {"error": "need at least 2 paths to merge"}
        
#         # 验证所有路径都存在且已完成
#         paths_to_merge = []
#         for pid in path_ids:
#             if pid not in self.paths:
#                 return {"error": f"path_id {pid} not found"}
#             path = self.paths[pid]
#             if path.status != "completed":
#                 return {"error": f"path {pid} is not completed, cannot merge"}
#             paths_to_merge.append(path)
        
#         # 检查路径相似度
#         if not self._are_paths_similar(paths_to_merge):
#             return {"error": "paths are not similar enough to merge"}
        
#         # 创建合并后的路径（使用第一条路径作为基础）
#         merged_path_id = self.allocate_path_id(self.current_function_info["function_name"])
#         merged_path = Path(merged_path_id, paths_to_merge[0].return_location, description)
#         merged_path.nodes = copy.deepcopy(paths_to_merge[0].nodes)
#         merged_path.edges = copy.deepcopy(paths_to_merge[0].edges)
#         merged_path.status = "completed"
#         merged_path.termination_type = paths_to_merge[0].termination_type
#         merged_path.termination_reason = f"Merged from paths: {', '.join(path_ids)}"
        
#         self.paths[merged_path_id] = merged_path
        
#         logger.info(f"[FunctionPathBuilderAgent] merge_paths merged {len(path_ids)} paths into {merged_path_id}")
#         return {"merged_path_id": merged_path_id, "merged_path": merged_path.to_dict()}
    
#     def _are_paths_similar(self, paths: List[Path]) -> bool:
#         """判断路径是否相似"""
#         if len(paths) < 2:
#             return True
        
#         # 检查节点类型序列
#         first_node_types = [n.node_type for n in paths[0].nodes]
#         for path in paths[1:]:
#             node_types = [n.node_type for n in path.nodes]
#             if node_types != first_node_types:
#                 return False
        
#         # 检查边的条件序列
#         first_edge_conditions = [e.conditions for e in paths[0].edges]
#         for path in paths[1:]:
#             edge_conditions = [e.conditions for e in path.edges]
#             if edge_conditions != first_edge_conditions:
#                 return False
        
#         # 检查终止状态
#         first_termination = paths[0].termination_type
#         for path in paths[1:]:
#             if path.termination_type != first_termination:
#                 return False
        
#         return True
    
#     def validate_path(self, path_id: str) -> Dict[str, Any]:
#         """验证路径的完整性"""
#         if path_id not in self.paths:
#             return {"error": f"path_id {path_id} not found"}
        
#         path = self.paths[path_id]
        
#         # 检查是否有起始节点
#         if len(path.nodes) == 0:
#             return {"error": "path has no nodes"}
        
#         # 检查节点和边的数量关系
#         # 对于n个节点，应该有n-1条边（如果路径已完成）
#         if path.status == "completed":
#             if len(path.edges) != len(path.nodes) - 1:
#                 return {"error": f"path has {len(path.nodes)} nodes but {len(path.edges)} edges. "
#                                f"Expected {len(path.nodes) - 1} edges"}
        
#         # 检查边的完整性
#         node_ids = {n.node_id for n in path.nodes}
#         for i, edge in enumerate(path.edges):
#             if edge.from_node_id not in node_ids:
#                 return {"error": f"edge {i} references non-existent from_node_id: {edge.from_node_id}"}
#             if edge.to_node_id not in node_ids:
#                 return {"error": f"edge {i} references non-existent to_node_id: {edge.to_node_id}"}
            
#             # 检查边的顺序
#             from_idx = next((j for j, n in enumerate(path.nodes) if n.node_id == edge.from_node_id), -1)
#             to_idx = next((j for j, n in enumerate(path.nodes) if n.node_id == edge.to_node_id), -1)
#             if from_idx >= to_idx:
#                 return {"error": f"edge {i} has invalid node order: from_node at index {from_idx}, "
#                                f"to_node at index {to_idx}"}
        
#         # 检查终止状态
#         if path.status == "completed":
#             if not path.termination_type:
#                 return {"error": "completed path must have termination_type"}
            
#             last_node = path.nodes[-1]
#             valid_termination_types = [
#                 "Deallocated", "Leak", "ReturnedAsReturnValue",
#                 "ReturnedAsPointerParameter", "NullPointer", "Unreachable"
#             ]
#             if last_node.node_type not in valid_termination_types:
#                 return {"error": f"last node type {last_node.node_type} is not a valid termination type"}
        
#         return {"ok": True, "path_id": path_id}
    
#     def _initialize_paths(self):
#         """根据return信息批量初始化路径，并设置当前活动路径"""
#         if not self.return_location_list:
#             placeholder_info = {
#                 "return_location": "",
#                 "completed_path_number": 0,
#                 "possible_path_list": [],
#                 "possible_path_number": 1
#             }
#             self.return_location_list.append(placeholder_info)
        
#         for return_location_info in self.return_location_list:
#             created_ids = self._create_paths_for_return_location(return_location_info)
#             return_location_info.setdefault("possible_path_list", []).extend(created_ids)
        
#         self.active_path_pointer = 0
#         self.active_path_id = None
#         self._set_next_active_path()
    
#     def _create_paths_for_return_location(self, return_location_info: Dict[str, Any]) -> List[str]:
#         """为指定return位置创建所需数量的路径"""
#         return_location = return_location_info.get("return_location", "")
#         possible_number = return_location_info.get("possible_path_number")
#         try:
#             path_count = int(possible_number) if possible_number is not None else 1
#         except (TypeError, ValueError):
#             path_count = 1
#         path_count = max(1, path_count)
        
#         created_ids: List[str] = []
#         for idx in range(path_count):
#             description_suffix = f" #{idx + 1}/{path_count}" if path_count > 1 else ""
#             description = f"Path{description_suffix} to {return_location or 'return'}"
#             path_id = self._create_path_instance(return_location, description)
#             created_ids.append(path_id)
#             self.path_to_return_location_map[path_id] = return_location_info
#         return created_ids
    
#     def _create_path_instance(self, return_location: str, description: str) -> str:
#         """创建单条路径并加入队列"""
#         path_id = self.allocate_path_id(self.current_function_info["function_name"])
#         path = Path(path_id, return_location, description)
        
#         if self.start_location and re.match(r'^[\w/]+\.(c|h|cpp):\d+$', self.start_location):
#             start_node_id = self.allocate_node_id(path_id)
#             var_name = self.var_info.get("var_name", "unknown")
#             try:
#                 start_code_line = find_code_line(self.start_location)
#             except Exception:
#                 start_code_line = ""
#             start_node = StateNode(
#                 start_node_id,
#                 "Initial",
#                 self.start_location,
#                 start_code_line,
#                 source_object=f"*{var_name}",
#                 target_object=None,
#                 metadata={"var_name": var_name, "var_type": self.var_info.get("var_type")}
#             )
#             path.add_node(start_node)
        
#         self.paths[path_id] = path
#         self.path_build_queue.append(path_id)
#         self.path_index_map[path_id] = len(self.path_build_queue) - 1
#         return path_id
    
#     def _ensure_active_path_id(self) -> Optional[str]:
#         """确保存在可用的活动路径，返回其ID"""
#         if self.active_path_id:
#             active_path = self.paths.get(self.active_path_id)
#             if active_path and active_path.status == "active":
#                 return self.active_path_id
        
#         return self._set_next_active_path()
    
#     def _set_next_active_path(self) -> Optional[str]:
#         """移动指针到下一个可用活动路径"""
#         while self.active_path_pointer < len(self.path_build_queue):
#             candidate_id = self.path_build_queue[self.active_path_pointer]
#             candidate_path = self.paths.get(candidate_id)
#             if candidate_path and candidate_path.status == "active":
#                 self.active_path_id = candidate_id
#                 return candidate_id
#             self.active_path_pointer += 1
#         self.active_path_id = None
#         return None
    
#     def _increment_completed_count(self, path_id: str):
#         """更新对应return位置的完成统计"""
#         info = self.path_to_return_location_map.get(path_id)
#         if info is not None:
#             info["completed_path_number"] = info.get("completed_path_number", 0) + 1
    
#     def _get_active_path_metadata(self) -> Optional[Dict[str, Any]]:
#         """获取当前活动路径的描述信息"""
#         path_id = self._ensure_active_path_id()
#         if not path_id:
#             return None
#         path = self.paths.get(path_id)
#         if not path:
#             return None
#         return {
#             "path_id": path_id,
#             "description": path.description,
#             "return_location": path.return_location
#         }
    
#     def build_paths(self):
#         """主工作流程：构建路径"""
#         # 获取所有可达的return位置
#         if self.var_info["var_type"] == "formal_arg":
#             arg_index = self.var_info["arg_index"]
#             wrapped_return_locations = analysis_operators.get_value_sensitive_arg_icfg_return_path(
#                 self.current_function_info["function_name"], arg_index)
#         elif self.var_info["var_type"] == "actual_arg":
#             arg_index = self.var_info["arg_index"]
#             wrapped_return_locations = analysis_operators.get_value_sensitive_call_arg_icfg_return_path(
#                 self.start_location, arg_index, "")
#         elif self.var_info["var_type"] == "local_var":
#             store_cl = self.var_info["arg_index"]
#             wrapped_return_locations = analysis_operators.get_value_sensitive_lvar_icfg_return_path(
#                 self.start_location, store_cl)
#         else:
#             wrapped_return_locations = []
        
#         # 初始化return_location_list
#         for wrapped_return_location in wrapped_return_locations:
#             location = wrapped_return_location.get('location', {})
#             if isinstance(location, dict):
#                 fl = location.get('fl', '')
#                 ln = location.get('ln', '')
#             else:
#                 fl = ''
#                 ln = ''
#             return_location_info = {
#                 "return_location": f"{fl}:{ln}" if fl and ln else "",
#                 "completed_path_number": 0,
#                 "possible_path_list": [],
#                 "possible_path_number": wrapped_return_location.get("mergeable_groups", 0)
#             }
#             if return_location_info["return_location"]:
#                 self.return_location_list.append(return_location_info)
        
#         # 为每个return位置创建初始路径和起始节点
#         self._initialize_paths()
        
#         # 构建提示词
#         var_prompt = self._build_var_prompt()
#         function_prompt = self._build_function_prompt()
#         return_prompt = self._build_return_prompt()
        
#         project_prompt = f"You are now working for project {PROJECT_NAME}. {PROJECT_DESC}\n"
        
#         messages = [
#             {"role": "system", "content": PATH_BUILDER_PROMPT + project_prompt},
#             {"role": "user", "content": var_prompt + function_prompt + return_prompt}
#         ]
        
#         # 发送消息并处理响应
#         allowed_tools = self._get_allowed_tools()
#         response = self.send_message(messages, allowed_tools)
        
#         if not response.content:
#             response.content = ""
#         messages.append(response)
        
#         # 处理工具调用循环
#         while True:
#             if not response.tool_calls:
#                 # 检查是否有未完成的路径
#                 incomplete_paths = [pid for pid, p in self.paths.items() if p.status == "active"]
#                 if incomplete_paths:
#                     current_path_meta = self._get_active_path_metadata()
#                     if current_path_meta:
#                         prompt_text = (
#                             f"仍有未完成的路径。请继续构建当前路径："
#                             f"{current_path_meta['description']} "
#                             f"(return {current_path_meta['return_location']})."
#                         )
#                     else:
#                         prompt_text = "仍有未完成的路径，请继续构建直至系统确认所有路径完成。"
#                     messages.append({
#                         "role": "user",
#                         "content": prompt_text
#                     })
#                     response = self.send_message(messages, allowed_tools)
#                     if not response.content:
#                         response.content = ""
#                     messages.append(response)
#                     continue
#                 break
            
#             # 处理每个工具调用
#             for tool_call in response.tool_calls:
#                 function_response = self.handle_agent_tool_call(tool_call)
#                 if not isinstance(function_response, str):
#                     function_response = json.dumps(function_response, ensure_ascii=False)
#                 messages.append({"tool_call_id": tool_call.id, "role": "tool", "content": function_response})
            
#             response = self.send_message(messages, allowed_tools)
#             if not response.content:
#                 response.content = ""
#             messages.append(response)
        
#         # 返回所有路径
#         return [path.to_dict() for path in self.paths.values()]
    
#     def _build_var_prompt(self) -> str:
#         """构建变量相关的提示词"""
#         var_name = self.var_info.get("var_name", "unknown")
#         var_type = self.var_info.get("var_type", "unknown")
        
#         if var_type == "formal_arg":
#             arg_index = self.var_info["arg_index"]
#             prompt = f"You are now tracing the memory of {var_name} in the function {self.current_function_info['function_name']}. "
#             prompt += f"The variable is the {arg_index + 1}th formal argument of this function."
#         elif var_type == "actual_arg":
#             arg_index = self.var_info["arg_index"]
#             prompt = f"You are now tracing the memory of {var_name} in the function {self.current_function_info['function_name']}. "
#             prompt += f"The variable is the {arg_index + 1}th actual argument."
#         elif var_type == "local_var":
#             prompt = f"You are now tracing the memory of {var_name} in the function {self.current_function_info['function_name']}. "
#             prompt += f"The variable is a local variable."
#         else:
#             prompt = f"You are now tracing the memory of {var_name} in the function {self.current_function_info['function_name']}."
        
#         # 添加GEP信息
#         gep_info = self.var_info.get("gep_info", {})
#         if gep_info.get("gep_type") == "baseobj":
#             prompt += f" The variable is a base object of a struct GEP operation. "
#             prompt += f"The base object name is {gep_info.get('baseobj_name')} and the member name is {gep_info.get('member_name')}."
#         elif gep_info.get("gep_type") == "member":
#             prompt += f" The variable is a member of a struct GEP operation. "
#             prompt += f"The base object name is {gep_info.get('baseobj_name')} and the member name is {gep_info.get('member_name')}."
        
#         return prompt + "\n"
    
#     def _build_function_prompt(self) -> str:
#         """构建函数相关的提示词"""
#         return f"The current function name is {self.current_function_info['function_name']}\n"
    
#     def _build_return_prompt(self) -> str:
#         """构建返回位置相关的提示词"""
#         prompt = f"All possible paths to the return locations of the function {self.current_function_info['function_name']} are as follows:\n"
#         for return_location_info in self.return_location_list:
#             return_location = return_location_info["return_location"]
#             possible_path_number = return_location_info.get("possible_path_number", 0)
#             prompt += f"There may be {possible_path_number} paths to the return location {return_location}.\n"
#         prompt += "Path identifiers are managed automatically by the system. Simply keep building nodes and edges until you finish all required paths.\n"
#         return prompt
    
#     def _get_allowed_tools(self):
#         """获取允许使用的工具列表"""
#         from tools import (
#             dump_source_snippet_desc_free,
#             dump_source_line_desc_free,
#             find_current_function_desc_free,
#             find_function_body_desc_free,
#             find_callers_desc_free,
#             add_state_node_desc_path_builder,
#             add_transition_edge_desc_path_builder,
#             complete_path_desc_path_builder,
#             create_custom_node_type_desc_path_builder
#         )
#         return [
#             dump_source_snippet_desc_free,
#             dump_source_line_desc_free,
#             find_current_function_desc_free,
#             find_function_body_desc_free,
#             find_callers_desc_free,
#             add_state_node_desc_path_builder,
#             add_transition_edge_desc_path_builder,
#             complete_path_desc_path_builder,
#             create_custom_node_type_desc_path_builder
#         ]

class FunctionNodeBuilderAgent:
    """函数值流节点构建Agent - 识别关键值流操作节点"""
    
    def __init__(self, var_info: Dict[str, Any], start_line: str, 
                 function_info: Dict[str, Any], client=None, model_name=None):
        """
        初始化FunctionNodeBuilderAgent
        
        Args:
            var_info: 变量信息，包含var_name, var_type, arg_index, gep_info等
            start_line: 分析起始行，格式如 "example.c:123"
            function_info: 函数信息，包含function_name等
            client: LLM客户端
            model_name: 模型名称
        """
        self.analysis_logger = setup_logger(log_type="analysis")
        self.var_info = var_info
        self.start_line = start_line
        self.function_info = function_info
        self.client = client
        self.model_name = model_name
        
        # 存储识别的值流节点
        self.value_flow_nodes: List[Dict[str, Any]] = []
        
        # 工具方法映射
        self.tool_method_map = {
            "add_value_flow_node": self.add_value_flow_node_Tool,
            "dump_source_snippet": self.dump_source_snippet_Tool,
            "dump_source_line": self.dump_source_line_Tool,
            "find_current_function": self.find_current_function_Tool,
            "find_function_body": self.find_function_body_Tool,
            "find_callers": self.find_callers_Tool,
        }
        
        print(f"[FunctionNodeBuilderAgent] init function={function_info.get('function_name')} "
              f"var={var_info.get('var_name')} start={start_line}")
        logger.info(f"[FunctionNodeBuilderAgent] init function={function_info.get('function_name')} "
                   f"var={var_info.get('var_name')} start={start_line}")
    
    def send_message(self, messages, tools=""):
        """发送消息到LLM"""
        tool_count = len(tools) if isinstance(tools, (list, tuple)) else (len(tools) if tools else 0)
        logger.info(f"[FunctionNodeBuilderAgent] send_message model={self.model_name} "
                   f"messages={len(messages)} tools={tool_count}")
        
        if not self.client:
            raise ValueError("LLM client not provided")
        
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools
        )
        response_message = response.choices[0].message
        tool_calls = getattr(response_message, "tool_calls", None) or []
        self._log_model_response(response_message, tool_calls)
        return response_message
    
    def _log_model_response(self, response_message, tool_calls):
        """记录模型返回内容"""
        if response_message is None:
            logger.debug("[FunctionNodeBuilderAgent] model_response: <empty response>")
            return
        content = getattr(response_message, "content", "") or ""
        if content and len(content) > 400:
            content = content[:400] + "...(truncated)"
        logger.debug(f"[FunctionNodeBuilderAgent] model_response: content={content or '<no content>'} "
                     f"tool_calls={len(tool_calls)}")
        print(f"[FunctionNodeBuilderAgent] model_response: content={content or '<no content>'} "
                     f"tool_calls={len(tool_calls)}")
    
    def handle_agent_tool_call(self, tool_call):
        """处理agent的工具调用"""
        function_name = "unknown"
        try:
            function_obj = getattr(tool_call, "function", tool_call)
            function_name = getattr(function_obj, "name", None)
            if not function_name:
                raise ValueError("missing function name in tool call")
            
            raw_arguments = getattr(function_obj, "arguments", "{}") or "{}"
            tool_arguments = safe_load_json(raw_arguments)
            
            logger.info(f"[FunctionNodeBuilderAgent] tool_call name={function_name} arguments={raw_arguments}")
            
            handler = self.tool_method_map.get(function_name)
            if handler is None:
                return {"error": f"unknown tool function: {function_name}"}
            
            if isinstance(tool_arguments, dict):
                result = handler(**tool_arguments)
            elif isinstance(tool_arguments, list):
                result = handler(*tool_arguments)
            else:
                result = handler(tool_arguments)
            print(f"[FunctionNodeBuilderAgent] tool_call result={result}")
            return result
        except Exception as e:
            return {"error": f"failed to execute tool {function_name}: {str(e)}"}
    
    # 源代码查询工具
    def dump_source_snippet_Tool(self, file_name, start_line, end_line):
        return analysis_operators.dump_source_snippet(file_name, start_line, end_line)
    
    def dump_source_line_Tool(self, file_name, line_number):
        return analysis_operators.dump_source_line(file_name, line_number)
    
    def find_current_function_Tool(self, source_location):
        return analysis_operators.find_current_function(source_location)
    
    def find_function_body_Tool(self, function_name):
        return analysis_operators.find_function_body(function_name)
    
    def find_callers_Tool(self, function_name):
        return analysis_operators.find_callers(function_name)
    
    # 值流节点构建工具
    def add_value_flow_node_Tool(self, node_type: str, location: str, code_line: str,
                                 source_object: Optional[str] = None,
                                 target_object: Optional[str] = None,
                                 callee_function_name: Optional[str] = None,
                                 param_name: Optional[str] = None,
                                 return_location: Optional[str] = None):
        """添加值流节点"""
        # 验证节点类型
        valid_types = [e.value for e in NodeType]
        if node_type not in valid_types:
            return {"error": f"unknown node_type: {node_type}. Valid types: {valid_types}"}
        
        # 使用 validate_source_location 验证 location 和 code_line
        validation_result = analysis_operators.validate_source_location(location, code_line)
        if "error" in validation_result:
            return {"error": f"location validation failed: {validation_result['error']}"}
        
        # 使用验证后修正的 location 和 code_line
        validated_location = validation_result["source_location"]
        validated_code_line = validation_result["code_line"]
        
        # 根据节点类型验证必需字段
        if node_type == "Transferred":
            if not source_object or not target_object:
                return {"error": "Transferred type requires source_object and target_object"}
        elif node_type == "HandledByCallee":
            if not callee_function_name or not param_name:
                return {"error": "HandledByCallee type requires callee_function_name and param_name"}
        elif node_type == "Deallocated":
            if not param_name:
                return {"error": "Deallocated type requires param_name"}
        elif node_type == "ReturnedAsPointerParameter":
            if not param_name:
                return {"error": "ReturnedAsPointerParameter type requires param_name"}
            if "return" not in code_line:
                return {"error": f"The code line {code_line} is not a return statement. Please check if the code line is correct."}
        elif node_type in ["Leak", "NullPointer"]:
            if not return_location:
                return {"error": f"{node_type} type requires return_location"}
            # 验证 return_location（不需要 code_line）
            return_loc_validation = analysis_operators.validate_source_location(return_location)
            if "error" in return_loc_validation:
                return {"error": f"return_location validation failed: {return_loc_validation['error']}"}
            # 使用验证后的 return_location
            return_location = return_loc_validation["source_location"]
        elif node_type == "ReturnedAsReturnValue":
            return_pointer_json = analysis_operators.check_return_pointer(return_location)
            if not return_pointer_json or not return_pointer_json["function_can_return_pointer"] or not return_pointer_json["location_has_pointer_operation"]:
                return {"error": f"The return location {return_location} is not a pointer or the function cannot return a pointer. Please check if the code line is correct."}
            
        # 构建节点字典
        node_dict = {
            "node_type": node_type,
            "location": validated_location,
            "code_line": validated_code_line,
        }
        
        # 添加类型特定字段
        if node_type == "Transferred":
            node_dict["source_object"] = source_object
            node_dict["target_object"] = target_object
        elif node_type == "HandledByCallee":
            node_dict["callee_function_name"] = callee_function_name
            node_dict["param_name"] = param_name
        elif node_type == "Deallocated":
            node_dict["param_name"] = param_name
        elif node_type == "ReturnedAsPointerParameter":
            node_dict["param_name"] = param_name
        elif node_type in ["Leak", "NullPointer"]:
            node_dict["return_location"] = return_location
        
        self.value_flow_nodes.append(node_dict)
        
        logger.info(f"[FunctionNodeBuilderAgent] add_value_flow_node node_type={node_type} location={location}")
        return {"success": True, "node": node_dict, "total_nodes": len(self.value_flow_nodes)}
    
    def identify_value_flow_nodes(self) -> List[Dict[str, Any]]:
        """主方法：识别关键值流节点"""
        # 构建提示词
        var_prompt = self._build_var_prompt()
        function_prompt = self._build_function_prompt()
        start_line_prompt = self._build_start_line_prompt()
        
        project_prompt = f"You are now working for project {PROJECT_NAME}. {PROJECT_DESC}\n"
        
        # 构建系统提示词
        system_prompt = self._build_system_prompt()
        
        messages = [
            {"role": "system", "content": system_prompt + project_prompt},
            {"role": "user", "content": var_prompt + function_prompt + start_line_prompt}
        ]
        
        # 发送消息并处理响应
        allowed_tools = self._get_allowed_tools()
        response = self.send_message(messages, allowed_tools)
        
        if not response.content:
            response.content = ""
        messages.append(response)
        
        # 处理工具调用循环
        max_iterations = 50  # 防止无限循环
        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            if not response.tool_calls:
                break
            
            # 处理每个工具调用
            for tool_call in response.tool_calls:
                function_response = self.handle_agent_tool_call(tool_call)
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response, ensure_ascii=False)
                messages.append({"tool_call_id": tool_call.id, "role": "tool", "content": function_response})
            
            response = self.send_message(messages, allowed_tools)
            if not response.content:
                response.content = ""
            messages.append(response)
        
        # 返回识别的值流节点列表
        return self.value_flow_nodes
    
    def _build_system_prompt(self) -> str:
        """构建系统提示词"""
        var_name = self.var_info.get("var_name", "unknown")
        prompt = f"""你正在追踪{var_name}变量的值流来侦测可能的内存泄漏问题
    静态分析的结果表明所有与当前值流相关的store语句 actualparam语句 gep语句展示如下
    StoreSVFGNode: tif_dirread.c:2337
    StoreSVFGNode: tif_dirread.c:2348
    StoreSVFGNode: tif_dirread.c:2359
    StoreSVFGNode: tif_dirread.c:2374
    StoreSVFGNode: tif_dirread.c:2389
    StoreSVFGNode: tif_dirread.c:2404
    StoreSVFGNode: tif_dirread.c:2419
    StoreSVFGNode: tif_dirread.c:2443
    StoreSVFGNode: tif_dirread.c:2460
    StoreSVFGNode: tif_dirread.c:2484
    StoreSVFGNode: tif_dirread.c:2510
    StoreSVFGNode: tif_dirread.c:2524
    你需要尽可能的削减这些值流节点并说明其他return位置的跨函数关键值流操作 来进行路径剪枝 
    你需要识别当前函数内的在内存申请: {self.start_line} 之后的所有必要关键的值流操作来帮助路径剪枝 你需要尽可能筛选掉不关键对分析内存泄漏不重要的值流操作
    值流操作需要被明确成值流节点 请使用以下节点类型来表示值流操作

    Transferred 表示值发生了转移 这既可能是通过赋值传递给了其他变量或者通过GEP操作转移给了BaseObj 也可能出于例如变长参数等特殊机制 你需要指出内存转移发生位置 说明内存由哪个变量被转移给了哪个变量

    HandledByCallee 表示内存将会被函数调用者处理 你需要指出函数调用在当前函数内发生的位置 由哪个函数被处理 并说明传入的参数名称是什么

    Deallocated 当且仅当指针被free或者用户自定义的free函数处理时 表示内存已经被释放 你需要指出调用内存释放函数发生位置 并说明传入的参数名称是什么

    ReturnedAsReturnValue 表示内存将会作为返回值返回 你需要指出函数返回的位置

    ReturnedAsPointerParameter 表示内存将会作为指针参数返回 你需要指出函数返回的位置 并给出是当前函数的哪一个参数接管了内存空间

    Leak 表示内存泄漏在当前函数发生了 你需要指定一个return位置 在这个return位置之后内存变量将变得unreachable

    NullPointer 表示内存将会被赋值为NULL 这往往由于内存申请失败导致 你需要指定一个return位置 表示在当前return之前 内存可能申请失败并且维持为空

    请仔细分析函数代码，识别所有关键的值流操作节点。
    """
        return prompt
    
    def _build_var_prompt(self) -> str:
        """构建变量相关的提示词"""
        var_name = self.var_info.get("var_name", "unknown")
        var_type = self.var_info.get("var_type", "unknown")
        
        if var_type == "formal_arg":
            arg_index = self.var_info.get("arg_index", 0)
            prompt = f"正在追踪变量 {var_name} 在函数 {self.function_info.get('function_name', 'unknown')} 中的值流。"
            prompt += f"该变量是该函数的第 {arg_index + 1} 个形式参数。"
        elif var_type == "actual_arg":
            arg_index = self.var_info.get("arg_index", 0)
            prompt = f"正在追踪变量 {var_name} 在函数 {self.function_info.get('function_name', 'unknown')} 中的值流。"
            prompt += f"该变量是该函数的第 {arg_index + 1} 个实际参数。"
        elif var_type == "local_var":
            prompt = f"正在追踪变量 {var_name} 在函数 {self.function_info.get('function_name', 'unknown')} 中的值流。"
            prompt += f"该变量是一个局部变量。"
        else:
            prompt = f"正在追踪变量 {var_name} 在函数 {self.function_info.get('function_name', 'unknown')} 中的值流。"
        
        # 添加GEP信息
        gep_info = self.var_info.get("gep_info", {})
        if gep_info.get("gep_type") == "baseobj":
            prompt += f" 该变量是结构体GEP操作的基对象。"
            prompt += f"基对象名称是 {gep_info.get('baseobj_name')}，成员名称是 {gep_info.get('member_name')}。"
        elif gep_info.get("gep_type") == "member":
            prompt += f" 该变量是结构体GEP操作的成员。"
            prompt += f"基对象名称是 {gep_info.get('baseobj_name')}，成员名称是 {gep_info.get('member_name')}。"
        
        return prompt + "\n"
    
    def _build_function_prompt(self) -> str:
        """构建函数相关的提示词"""
        function_name = self.function_info.get("function_name", "unknown")
        function_body = self.function_info.get("function_body", "")
        
        prompt = f"当前函数名称是 {function_name}\n"
        if function_body:
            prompt += f"函数体如下：\n{function_body}\n"
        
        return prompt
    
    def _build_start_line_prompt(self) -> str:
        """构建起始行相关的提示词"""
        return f"分析的起始位置是 {self.start_line}。请从该位置开始分析值流操作。\n"
    
    def _get_allowed_tools(self):
        """获取允许使用的工具列表"""
        from tools import (
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            add_value_flow_node_desc_node_builder
        )
        return [
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
            add_value_flow_node_desc_node_builder
        ]


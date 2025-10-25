import collections

class FunctionNode:
    """
    代表调用图中的一个节点（一个函数）。
    """
    def __init__(self, function_info):
        self.name = function_info["function_name"]
        self.filename = function_info["filename"]
        self.start_line = function_info["start_line"]
        self.end_line = function_info["end_line"]
        self.function_body = function_info["function_body"]

        # 核心结构：
        # 1. self.callees: 这个函数调用了谁？
        #    - 格式: { FunctionNode_callee: [line1, line2, ...] }
        #    - 记录了它在哪些行调用了另一个函数（callee）
        self.callees = collections.defaultdict(list)

        # 2. self.callers: 谁调用了这个函数？
        #    - 格式: { FunctionNode_caller: [line1, line2, ...] }
        #    - 记录了另一个函数（caller）在哪些行调用了它
        self.callers = collections.defaultdict(list)

    def add_callee(self, callee_node, line_number):
        if line_number not in self.callees[callee_node]:
            self.callees[callee_node].append(line_number)

    def add_caller(self, caller_node, line_number):
        if line_number not in self.callers[caller_node]:
            self.callers[caller_node].append(line_number)

    def __repr__(self):
        # # 定义一个清晰的打印格式，方便调试
        # return f"<FunctionNode: {self.filename}:{self.name}>"
        return

class CallGraph:
    def __init__(self):
        self.nodes = {}

    def create_node(self, function_info):
        if function_info["function_name"] not in self.nodes:
            self.nodes[function_info["function_name"]] = FunctionNode(function_info)
        return 

    def create_call(self, caller_function_info, callee_function_info, call_line):
        if caller_function_info["function_name"] not in self.nodes:
            self.nodes[caller_function_info["function_name"]] = FunctionNode(caller_function_info)
        if callee_function_info["function_name"] not in self.nodes:
            self.nodes[callee_function_info["function_name"]] = FunctionNode(callee_function_info)
        self.nodes[caller_function_info["function_name"]].add_callee(self.nodes[callee_function_info["function_name"]], call_line)
        self.nodes[callee_function_info["function_name"]].add_caller(self.nodes[caller_function_info["function_name"]], call_line)
        return 

    def print_summary(self):
        # """
        # 打印整个调用图的摘要信息。
        # """
        # if not self.nodes:
        #     print("Call graph is empty.")
        #     return

        # print("="*30)
        # print("      Call Graph Summary")
        # print("="*30)
        
        # for node in sorted(self.nodes.values(), key=lambda n: (n.filename, n.name)):
        #     print(f"\nFunction: {node.name} (in {node.filename})")
        #     if node.info:
        #         print(f"  Info: {node.info}")

        #     # 打印它调用的函数
        #     if not node.callees:
        #         print("  -> Calls: None")
        #     else:
        #         print("  -> Calls:")
        #         for callee_node, lines in node.callees.items():
        #             print(f"    - {callee_node.name} (at line(s): {sorted(lines)})")

        #     # 打印调用它的函数
        #     if not node.callers:
        #         print("  <- Called by: None")
        #     else:
        #         print("  <- Called by:")
        #         for caller_node, lines in node.callers.items():
        #             # 这里的 'lines' 是指 caller_node 中的行号
        #             print(f"    - {caller_node.name} (from line(s): {sorted(lines)})")
        return
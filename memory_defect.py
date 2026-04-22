from utils import *

def _code_line_for_loc(source_loc):
    """source_loc dict or str -> code line string."""
    d = normalize_source_loc(source_loc)
    if d:
        return find_code_line_fl_ln(d["fl"], d["ln"])
    if isinstance(source_loc, str):
        return find_code_line(source_loc)
    return None


class MemoryDefect:
    def __init__(self, defect_type, source_loc):
        # source_loc: dict {"fl","ln","cl"?} from SAR json.loads, or legacy string "file:line"
        self.defect_type = defect_type
        self._source_loc = normalize_source_loc(source_loc)
        if self._source_loc is None and isinstance(source_loc, str):
            self._source_loc = parse_source_location_to_fl_ln(source_loc)
            if self._source_loc is not None:
                self._source_loc["cl"] = None

    @property
    def source_location(self):
        """Location string for prompts and find_code_line; derived from fl/ln."""
        if self._source_loc:
            return source_loc_to_string(self._source_loc["fl"], self._source_loc["ln"])
        return None

    def get_source_loc(self):
        """Structured fl/ln/cl for send_query."""
        return self._source_loc

    def get_defect_type(self):
        return self.defect_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        loc = self.source_location
        line = _code_line_for_loc(self._source_loc) or ""
        return f"Potential {self.defect_type} for {extract_lhs_variable(line)} at {loc}"

    def to_goal_prompt(self):
        return (
            f"You are looking for potential {self.defect_type} memory issues "
            f"related to the memory allocated at {self.source_location}. "
            f"This issue is considered to occur if "
        )


class MemoryLeak(MemoryDefect):
    def __init__(self, leak_type=None, source_loc=None):
        super().__init__("MemoryLeak", source_loc)
        self.leak_type = leak_type

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        return super().to_prompt()

    def to_goal_prompt(self):
        return super().to_goal_prompt()


class NeverFree(MemoryLeak):
    def __init__(self, source_loc=None):
        super().__init__("NeverFree", source_loc)

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        loc = self.source_location
        line = _code_line_for_loc(self._source_loc) or ""
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        Guidance_prompt = (
            "Guidance on triaging this type of bug based on memory reachability: "
            "The warning at a specific source line is a false positive if the memory will be properly freed along all execution paths. \n"
        )
        Location_prompt = f"Source location: {loc}  \n"
        Code_prompt = f"Source code at {loc} here is : {line}\n"
        variable_name = extract_lhs_variable(line)
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {loc} may not be freed along certain execution paths.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {loc} may not be freed along certain execution paths.  \n"
        Task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Task_prompt

    def to_goal_prompt(self):
        return super().to_goal_prompt() + "upon reaching the end of the function, the memory has become unreachable and can never be freed."


class PartialLeak(MemoryLeak):
    class conditional_path:
        def __init__(self, condition=None, condition_loc=None):
            self.condition = condition
            self._condition_loc = normalize_source_loc(condition_loc) if condition_loc else None

        def get_condition(self):
            return self.condition

        def get_condition_location(self):
            if self._condition_loc:
                return source_loc_to_string(self._condition_loc["fl"], self._condition_loc["ln"])
            return None

    def __init__(self, source_loc=None, conditional_free_paths=None):
        if conditional_free_paths is None:
            conditional_free_paths = []
        super().__init__("PartialLeak", source_loc)
        self.conditional_free_paths = conditional_free_paths

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        loc = self.source_location
        line = _code_line_for_loc(self._source_loc) or ""
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        Guidance_prompt = (
            "Guidance on triaging this type of bug based on memory reachability: "
            "The warning at a specific source line is a false positive if the memory will be properly freed along all execution paths. \n"
        )
        Location_prompt = f"Source location: {loc}  \n"
        Code_prompt = f"Source code at {loc} here is : {line}\n"
        variable_name = extract_lhs_variable(line)
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {loc} may not be freed along certain execution paths .  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {loc} may not be freed along certain execution paths .  \n"
        Task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Task_prompt

    def to_goal_prompt(self):
        return super().to_goal_prompt() + "upon reaching the end of the function, the memory has become unreachable and can never be freed."


class DoubleFree(MemoryLeak):
    class double_path:
        def __init__(self, condition=None, double_loc=None):
            self.condition = condition
            self._double_loc = normalize_source_loc(double_loc) if double_loc else None

        def get_condition(self):
            return self.condition

        def get_double_location(self):
            if self._double_loc:
                return source_loc_to_string(self._double_loc["fl"], self._double_loc["ln"])
            return None

    def __init__(self, source_loc, double_free_paths=None):
        if double_free_paths is None:
            double_free_paths = []
        super().__init__("DoubleFree", source_loc)
        self.double_free_paths = double_free_paths

    def get_leak_type(self):
        return self.leak_type

    def get_double_free_paths(self):
        return self.double_free_paths

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        loc = self.source_location
        line = _code_line_for_loc(self._source_loc) or ""
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        Guidance_prompt = "Guidance on triaging this type of bug: The warning at a specific source line is a false positive if \n"
        Location_prompt = f"Source location: {loc}  \n"
        Code_prompt = f"Source code at {loc} here is : {line}\n"
        variable_name = extract_lhs_variable(line)
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {loc} is double freed.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {loc} is double freed.  \n"
        if self.double_free_paths:
            Message_prompt += "There exists at least one path that leads to a double free, and this path requires "
            for cond_path in self.double_free_paths:
                Message_prompt += f" the condition at {cond_path.get_double_location()} to be'{cond_path.get_condition()}'"
                Message_prompt += " and"
            Message_prompt = Message_prompt[:-4] + ".\n"
        Task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Code_prompt + Task_prompt

    def to_goal_prompt(self):
        return super().to_goal_prompt() + "there exists a path on control-flow that the same memory is freed more than once without a reallocation in between."


class UseAfterFree(MemoryDefect):
    class UseNode:
        def __init__(self, use_loc=None, condition=None, condition_loc=None):
            self._use_loc = normalize_source_loc(use_loc) if use_loc else None
            self.condition = condition
            self._condition_loc = normalize_source_loc(condition_loc) if condition_loc else None

        def get_use_location(self):
            if self._use_loc:
                return source_loc_to_string(self._use_loc["fl"], self._use_loc["ln"])
            return None

        def get_condition(self):
            return self.condition

        def get_condition_location(self):
            if self._condition_loc:
                return source_loc_to_string(self._condition_loc["fl"], self._condition_loc["ln"])
            return None

    class NodePair:
        def __init__(self, free_loc, use_nodes):
            self._free_loc = normalize_source_loc(free_loc) if free_loc else None
            self.use_nodes = use_nodes

        def get_free_location(self):
            if self._free_loc:
                return source_loc_to_string(self._free_loc["fl"], self._free_loc["ln"])
            return None

        def get_use_nodes(self):
            return self.use_nodes

    def __init__(self, source_loc, node_pairs):
        super().__init__("UseAfterFree", source_loc)
        self.node_pairs = node_pairs

    def get_node_pairs(self):
        return self.node_pairs

    def to_prompt(self):
        loc = self.source_location
        type_prompt = f"Type of bug: {self.defect_type}.\n"
        guidance_prompt = (
            "Guidance on triaging this type of bug:\n"
            "The warning is a true positive (TP) if:\n"
            "  - There exists a feasible execution path where memory is freed and then used without reallocation\n"
            "  - The use occurs after the free in program execution order\n"
            "  - The same memory block is accessed after being freed\n\n"
            "The warning is a false positive (FP) if:\n"
            "  - The free and use are on mutually exclusive paths\n"
            "  - The pointer is reallocated before use\n"
            "  - The use occurs before the free in execution order\n"
            "  - Different memory blocks are involved in free and use operations\n"
        )
        alloc_line = _code_line_for_loc(self._source_loc) or ""
        alloc_prompt = f"Memory allocation at: {loc}\n"
        alloc_code = f"Allocation code: {alloc_line}\n\n"

        nodes_prompt = "Free-Use Node Pairs:\n"
        for i, pair in enumerate(self.node_pairs):
            free_loc = pair.get_free_location()
            nodes_prompt += f"Pair {i + 1}:\n"
            nodes_prompt += f"  Free at: {free_loc}\n"
            free_line = _code_line_for_loc(pair._free_loc) if pair._free_loc else find_code_line(free_loc) if free_loc else ""
            nodes_prompt += f"  Free code: {free_line}\n"

            nodes_prompt += "  Use sites after this free:\n"
            for use_node in pair.get_use_nodes():
                use_loc = use_node.get_use_location()
                nodes_prompt += f"    - Use at: {use_loc}\n"
                use_line = _code_line_for_loc(use_node._use_loc) if use_node._use_loc else find_code_line(use_loc) if use_loc else ""
                nodes_prompt += f"      Use code: {use_line}\n"

                condition = use_node.get_condition()
                condition_location = use_node.get_condition_location()
                if condition and condition_location:
                    nodes_prompt += f"      Condition '{condition}' at {condition_location}\n"

            nodes_prompt += "\n"

        alloc_line_for_var = _code_line_for_loc(self._source_loc) or ""
        variable_name = extract_lhs_variable(alloc_line_for_var)
        if variable_name is None:
            variable_name = "unknown"
        message_prompt = (
            f"Message: Memory allocated to '{variable_name}' at {loc} "
            "is accessed after being freed in the paths shown above. "
            "This results in undefined behavior and potential security vulnerabilities.\n\n"
        )

        task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."

        return (
            type_prompt
            + guidance_prompt
            + alloc_prompt
            + alloc_code
            + nodes_prompt
            + message_prompt
            + task_prompt
        )

    def to_goal_prompt(self):
        return (
            super().to_goal_prompt()
            + "there exists a path on control-flow that memory is freed and then used without reallocation in between."
        )


class BufferOverflow(MemoryDefect):
    """缓冲区溢出：source_loc 为分析器报告的源码位置（dbg fl/ln），与 run.py 按位置去重一致。"""

    def __init__(
        self,
        source_loc,
        val_var_id=None,
        ir_instruction=None,
        buffer_index_text=None,
        buffer_size_text=None,
    ):
        super().__init__("BufferOverflow", source_loc)
        self.val_var_id = val_var_id
        self.ir_instruction = ir_instruction
        self.buffer_index_text = buffer_index_text
        self.buffer_size_text = buffer_size_text

    def get_val_var_id(self):
        return self.val_var_id

    def get_ir_instruction(self):
        return self.ir_instruction

    def get_buffer_index_text(self):
        return self.buffer_index_text

    def get_buffer_size_text(self):
        return self.buffer_size_text

    def to_prompt(self):
        loc = self.source_location
        type_prompt = f"Type of bug: {self.defect_type}.\n"
        guidance_prompt = (
            "Guidance on triaging this type of bug:\n"
            "The warning is a true positive (TP) if:\n"
            "  - There exists a feasible path where the accessed index/offset lies outside the valid buffer bounds\n"
            "  - The buffer size and index ranges from the analyzer are consistent with an out-of-bounds access\n\n"
            "The warning is a false positive (FP) if:\n"
            "  - Infeasible path constraints make the overflow unreachable\n"
            "  - The analyzer over-approximated buffer size or under-approximated valid index range\n"
            "  - A larger allocation or different object is actually used at runtime than modeled\n"
        )
        site_line = _code_line_for_loc(self._source_loc) or ""
        site_prompt = f"Alert source location: {loc}\n"
        site_code = f"Source code at alert site: {site_line}\n\n"

        detail_prompt = "Checker details:\n"
        if self.val_var_id is not None:
            detail_prompt += f"  ValVar ID: {self.val_var_id}\n"
        if self.ir_instruction:
            detail_prompt += f"  LLVM IR (with dbg): {self.ir_instruction}\n"
        if self.buffer_index_text:
            detail_prompt += f"  Buffer index: {self.buffer_index_text}\n"
        if self.buffer_size_text:
            detail_prompt += f"  Buffer size: {self.buffer_size_text}\n"
        detail_prompt += "\n"

        message_prompt = (
            f"Message: A buffer overflow may occur at {loc} according to the index/size "
            "ranges above relative to the modeled buffer.\n\n"
        )
        task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."

        return (
            type_prompt
            + guidance_prompt
            + site_prompt
            + site_code
            + detail_prompt
            + message_prompt
            + task_prompt
        )

    def to_goal_prompt(self):
        return (
            super().to_goal_prompt()
            + "there exists a feasible execution where a memory access exceeds the allocated buffer bounds."
        )

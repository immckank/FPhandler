from utils import *

class MemoryDefect:
    def __init__(self, defect_type, source_location):
        # 构造时传入的source_location都是 文件名 : 行号
        self.defect_type = defect_type
        self.source_location = source_location

    def get_defect_type(self):
        return self.defect_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        return f"{self.defect_type} at {self.source_location}"
    
    def to_base_prompt(self):
        # Potential <Error Type> for <Variable Name> at <Location>.
        return f"Potential {self.defect_type} for {extract_lhs_variable(find_code_line(self.source_location))} at {self.source_location}"
    
class MemoryLeak(MemoryDefect):
    def __init__(self, leak_type=None, source_location=None):
        super().__init__("MemoryLeak", source_location)
        self.leak_type = leak_type
        self.source_location = source_location
        
    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        return super().to_prompt()

class NeverFree(MemoryLeak):
    def __init__(self, source_location=None):
        super().__init__("NeverFree", source_location)

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        Guidance_prompt = ("Guidance on triaging this type of bug based on memory reachability: " 
            "The warning at a specific source line is a false positive if " 
                "the memory has been freed, or it remains accessible to the program after the function exits and can be freed later. "
                "(This usually happens if the pointer is the function's return value, stored in a global variable, or passed to an output parameter.) "
            "The warning at a specific source line is a true positive if "
                "there exist a path on control-flow that reaches the end of the function without freeing the memory. Upon the function's exit, the memory has become unreachable and can never be freed.\n")
        Location_prompt = f"Source location: {self.source_location}  \n"
        Code_prompt = f"Source code at {self.source_location} here is : {find_code_line(self.source_location)}\n"
        variable_name = extract_lhs_variable(find_code_line(self.source_location))
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {self.source_location} may not be freed along all the paths that reach the end of the function.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {self.source_location} may not be freed along all paths that reach the end of the function.  \n"
        Task_prompt = f"Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Code_prompt + Task_prompt

class PartialLeak(MemoryLeak):
    class conditional_path:
        def __init__(self, condition=None, condition_location=None):
            self.condition = condition
            self.condition_location = condition_location
        
        def get_condition(self):
            return self.condition
        
        def get_condition_location(self):
            return self.condition_location
    
    def __init__(self, source_location=None, conditional_free_paths=[]):
        super().__init__("PartialLeak", source_location)
        self.conditional_free_paths = conditional_free_paths

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        Guidance_prompt = ("Guidance on triaging this type of bug based on memory reachability: " 
            "The warning at a specific source line is a false positive if " 
                "the memory has been freed, or it remains accessible to the program after the function exits and can be freed later. "
                "(This usually happens if the pointer is the function's return value, stored in a global variable, or passed to an output parameter.) "
            "The warning at a specific source line is a true positive if "
                "there exist a path on control-flow that reaches the end of the function without freeing the memory. Upon the function's exit, the memory has become unreachable and can never be freed.\n")
        Location_prompt = f"Source location: {self.source_location}  \n"
        Code_prompt = f"Source code at {self.source_location} here is : {find_code_line(self.source_location)}\n"
        variable_name = extract_lhs_variable(find_code_line(self.source_location))
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {self.source_location} may not be freed along some paths that reach the end of the function.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {self.source_location} may not be freed along some paths that reach the end of the function.  \n"
        if self.conditional_free_paths:
            Message_prompt += "There exists at least one path that can free the memory, and this path requires"
            for idx, cond_path in enumerate(self.conditional_free_paths):
                Message_prompt += f" the condition at {cond_path.get_condition_location()} to be '{cond_path.get_condition()}'"
                Message_prompt += f" and"
            Message_prompt = Message_prompt[:-4] + ".\n"
        Task_prompt = f"Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Task_prompt

class DoubleFree(MemoryLeak):
    class double_path:
        def __init__(self, condition=None, double_location=None):
            self.condition = condition
            self.double_location = double_location

        def get_condition(self):
            return self.condition

        def get_double_location(self):
            return self.double_location

    def __init__(self, source_location, double_free_paths=[]):
        super().__init__("DoubleFree", source_location)
        self.double_free_paths = double_free_paths

    def get_leak_type(self):
        return self.leak_type

    def get_double_free_paths(self):
        return self.double_free_paths

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        Type_prompt = f"Type of bug: {self.leak_type}. \n"
        # TP if a feasible control-flow path exists in which the same memory is freed more than once without a reallocation in between.
        Guidance_prompt = f"Guidance on triaging this type of bug: The warning at a specific source line is a false positive if \n"
        Location_prompt = f"Source location: {self.source_location}  \n"
        Code_prompt = f"Source code at {self.source_location} here is : {find_code_line(self.source_location)}\n"
        variable_name = extract_lhs_variable(find_code_line(self.source_location))
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {self.source_location} is double freed.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {self.source_location} is double freed.  \n"
        if self.double_free_paths:
            Message_prompt += "There exists at least one path that leads to a double free, and this path requires "
            for idx, cond_path in enumerate(self.conditional_free_paths):
                Message_prompt += f" the condition at {cond_path.get_condition_location()} to be'{cond_path.get_condition()}'"
                Message_prompt += f" and"
            Message_prompt = Message_prompt[:-4] + ".\n"
        Task_prompt = f"Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Code_prompt + Message_prompt + Code_prompt + Task_prompt


class UseAfterFree(MemoryDefect):
    class UseNode:
        def __init__(self, use_location, condition=None, condition_location=None):
            self.use_location = use_location
            self.condition = condition
            self.condition_location = condition_location

        def get_use_location(self):
            return self.use_location

        def get_condition(self):
            return self.condition

        def get_condition_location(self):
            return self.condition_location

    class NodePair:
        def __init__(self, free_location, use_nodes):
            self.free_location = free_location
            self.use_nodes = use_nodes  # list of UseNode objects

        def get_free_location(self):
            return self.free_location

        def get_use_nodes(self):
            return self.use_nodes

    def __init__(self, source_location, node_pairs):
        super().__init__("UseAfterFree", source_location)
        self.node_pairs = node_pairs  # list of NodePair objects

    def get_node_pairs(self):
        return self.node_pairs

    def to_prompt(self):
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
        alloc_prompt = f"Memory allocation at: {self.source_location}\n"
        alloc_code = f"Allocation code: {find_code_line(self.source_location)}\n\n"

        nodes_prompt = "Free-Use Node Pairs:\n"
        for i, pair in enumerate(self.node_pairs):
            free_loc = pair.get_free_location()
            nodes_prompt += f"Pair {i + 1}:\n"
            nodes_prompt += f"  Free at: {free_loc}\n"
            nodes_prompt += f"  Free code: {find_code_line(free_loc)}\n"

            nodes_prompt += "  Use sites after this free:\n"
            for use_node in pair.get_use_nodes():
                use_loc = use_node.get_use_location()
                nodes_prompt += f"    - Use at: {use_loc}\n"
                nodes_prompt += f"      Use code: {find_code_line(use_loc)}\n"

                # 添加条件路径信息
                condition = use_node.get_condition()
                condition_location = use_node.get_condition_location()
                if condition and condition_location:
                    nodes_prompt += f"      Condition '{condition}' at {condition_location}\n"

            nodes_prompt += "\n"

        variable_name = extract_lhs_variable(find_code_line(self.source_location))
        if variable_name is None:
            variable_name = "unknown"
        message_prompt = (
            f"Message: Memory allocated to '{variable_name}' at {self.source_location} "
            "is accessed after being freed in the paths shown above. "
            "This results in undefined behavior and potential security vulnerabilities.\n\n"
        )

        task_prompt = "Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."

        return (
                type_prompt +
                guidance_prompt +
                alloc_prompt +
                alloc_code +
                nodes_prompt +
                message_prompt +
                task_prompt
        )

import utils

'''prompt format
Type of bug: PartialLeak.
TODO: Guidance on triaging this type of bug: The warning at a specific source line is a false positive if    
Source location: memcached/slab_automove.c:37
Message: The variable 'a' allocated at memcached/slab_automove.c:37 may not be freed along some paths that reach the end of the function.
The following are the conditions and locations of conditional free paths:
  Path 1: Condition 'True' at memcached/slab_automove.c:43
TODO: Function code:
Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning.
'''

class MemoryDefect:
    def __init__(self, defect_type, source_location):
        self.defect_type = defect_type
        self.source_location = source_location

    def get_defect_type(self):
        return self.defect_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        return f"{self.defect_type} at {self.source_location}"
    
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
        Guidance_prompt = f"Guidance on triaging this type of bug: The warning at a specific source line is a false positive if the memory has been freed, or it has been transferred to a longer-lived context.\n"
        Location_prompt = f"Source location: {self.source_location}  \n"
        variable_name = utils.extract_lhs_variable(utils.find_code_line(self.source_location))
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {self.source_location} may not be freed along all the paths that reach the end of the function.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {self.source_location} may not be freed along all paths that reach the end of the function.  \n"
        # TODO: Function code:
        # Code_prompt = f"TODO: Function code:  \n"
        Code_prompt = f""
        Task_prompt = f"Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Message_prompt + Code_prompt + Task_prompt

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
        # TODO: Guidance on triaging this type of bug:
        Guidance_prompt = f"Guidance on triaging this type of bug: The warning at a specific source line is a false positive if \n"
        Location_prompt = f"Source location: {self.source_location}  \n"
        variable_name = utils.extract_lhs_variable(utils.find_code_line(self.source_location))
        if variable_name:
            Message_prompt = f"Message: The variable '{variable_name}' allocated at {self.source_location} may not be freed along some paths that reach the end of the function.  \n"
        else:
            Message_prompt = f"Message: The memory allocated at {self.source_location} may not be freed along some paths that reach the end of the function.  \n"
        if self.conditional_free_paths:
            Message_prompt += "The following are the conditions and locations of conditional free paths:\n"
            for idx, cond_path in enumerate(self.conditional_free_paths):
                Message_prompt += f"  Path {idx+1}: Condition '{cond_path.get_condition()}' at {cond_path.get_condition_location()}\n"
        Code_prompt = f"TODO: Function code:  \n"
        Task_prompt = f"Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning."
        return Type_prompt + Guidance_prompt + Location_prompt + Message_prompt + Code_prompt + Task_prompt

class DoubleFree(MemoryDefect):
    def __init__(self, source_location):
        super().__init__("DoubleFree", source_location)

    def to_prompt(self):
        return super().to_prompt()

class UseAfterFree(MemoryDefect):
    def __init__(self, source_location):
        super().__init__("UseAfterFree", source_location)

    def to_prompt(self):
        return super().to_prompt()
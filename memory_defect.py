'''prompt format

Type of bug: cpp/uninitialized-local. 
Guidance on triaging this type of bug: The warning at a specific source line is a false positive if the variable is always initialized along all the paths that reach that line.  
Source location: find/tree.c:565  
Message: The variable [left_cost](1) may not be initialized at this access. (1) find/tree.c:518:7  
:: Function code: [omitted]  
Task: Please classify this alert as TP, FP, or UNCERTAIN, and provide your reasoning

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
        # TODO: Guidance on triaging this type of bug:
        Guidance_prompt = f"Guidance on triaging this type of bug: The warning at a specific source line is a false positive if \n"
        Location_prompt = f"Source location: {self.source_location}  \n"
        return f"{self.leak_type} at {self.source_location}"

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
        basic_info = f"{self.leak_type} at {self.source_location} with {len(self.conditional_free_paths)} conditional free paths"
        cond_info = ""
        for idx, cond_path in enumerate(self.conditional_free_paths):
            cond_info += f"\n  Path {idx+1}: Condition '{cond_path.get_condition()}' at {cond_path.get_condition_location()}"
        return basic_info + cond_info


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
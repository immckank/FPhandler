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
        return f""
    
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
        return ""

class NeverFree(MemoryLeak):
    def __init__(self, source_location=None):
        super().__init__("NeverFree", source_location)

    def get_leak_type(self):
        return self.leak_type

    def get_source_location(self):
        return self.source_location

    def to_prompt(self):
        return ""

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
        return ""


class DoubleFree(MemoryDefect):
    def __init__(self, source_location):
        super().__init__("DoubleFree", source_location)

    def to_prompt(self):
        return f"Double free detected at {self.source_location}"


class UseAfterFree(MemoryDefect):
    def __init__(self, source_location):
        super().__init__("UseAfterFree", source_location)

    def to_prompt(self):
        return f"Use after free detected at {self.source_location}"
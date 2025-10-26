# Free analyzer tool descriptions
set_conclusion_desc_free = {
    "type": "function",
    "function": {
        "name": "set_conclusion",
        "description": "Sets the final conclusion for an alert analysis. This function should be called at the end of an analysis to provide a definitive classification and the reasoning behind it.",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification of the alert, must be one of 'FP' (False Positive), 'TP' (True Positive), or 'UNCERTAIN'.",
                    "enum": ["FP", "TP", "UNCERTAIN"]
                },
                "reason": { "type": "string", "description": "A detailed explanation for the given classification."}
            },
            "required": ["classification", "reason"]
        }
    }
}

dump_source_snippet_desc_free = {
    "type": "function",
    "function": {
        "name": "dump_source_snippet",
        "description": "Dumps a snippet of source code from a file between the given line numbers.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                "start_line": {"type": "integer", "description": "The starting line number (inclusive)."},
                "end_line": {"type": "integer", "description": "The ending line number (inclusive)."}
            },
            "required": ["file_name", "start_line", "end_line"]
        }
    }
}

dump_source_line_desc_free = {
    "type": "function",
    "function": {
        "name": "dump_source_line",
        "description": "Dumps a single line of source code from a file.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                "line_number": {"type": "integer", "description": "The line number to retrieve."}
            },
            "required": ["file_name", "line_number"]
        }
    }
}

find_current_function_desc_free = {
    "type": "function",
    "function": {
        "name": "find_current_function",
        "description": "Finds the function in which the given source location exists.",
        "parameters": {
            "type": "object",
            "properties": { "source_location": {"type": "string", "description": "The source location, in the format 'filename.c:line_number'."} },
            "required": ["source_location"]
        }
    }
}

find_function_body_desc_free = {
    "type": "function",
    "function": {
        "name": "find_function_body",
        "description": "Finds the function body by its name.",
        "parameters": {
            "type": "object",
            "properties": { "function_name": {"type": "string", "description": "The name of the function to find."} },
            "required": ["function_name"]
        }
    }
}

find_callers_desc_free = {
    "type": "function",
    "function": {
        "name": "find_callers",
        "description": "Finds all functions that call a given target function.",
        "parameters": {
            "type": "object",
            "properties": { "function_name": {"type": "string", "description": "The name of the target function to find callers for."} },
            "required": ["function_name"]
        }
    }
}

# Function analyzer tool descriptions
check_source_line_desc_function = {
    "type": "function",
    "function": {
        "name": "check_source_line",
        "description": "Dumps a single line of source code from a file and check whether it is in the current function.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                "line_number": {"type": "integer", "description": "The line number of the source code."}
            },
            "required": ["file_name", "line_number"]
        }
    }
}

check_source_snippet_desc_function = {
    "type": "function",
    "function": {
        "name": "check_source_snippet", 
        "description": "Dumps code snippet of source code inside current function from a file between the given line numbers.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_name": {"type": "string", "description": "The name of the file relative to the project root."},
                "start_line": {"type": "integer", "description": "The starting line number of the snippet."},
                "end_line": {"type": "integer", "description": "The ending line number of the snippet."}
            },
            "required": ["file_name", "start_line", "end_line"]
        }
    }
}

call_function_desc_function = {
    "type": "function",
    "function": {
        "name": "call_function",
        "description": "Get to work in a new function called by the current function.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "The name of the function to call."},
                "line_number": {"type": "integer", "description": "The line number where the function is called."}
            },
            "required": ["function_name", "line_number"]
        }
    }
}

return_function_desc_function = {
    "type": "function",
    "function": {
        "name": "return_function",
        "description": "Return to the caller of the current function. If the current function is the initial function of the analysis, this action will find all its call sites to create a worklist for further investigation.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}

check_current_function_desc_function = {
    "type": "function",
    "function": {
        "name": "check_current_function",
        "description": "Check the current function name and function body in source code.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}

check_call_stack_desc_function = {
    "type": "function",
    "function": {
        "name": "check_call_stack",
        "description": "Check your call chain to the current function.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}

get_back_to_initial_function_desc_function = {
    "type": "function",
    "function": {
        "name": "get_back_to_initial_function",
        "description": "Get back to the initial function of the analysis.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}

jump_to_function_desc_function = {
    "type": "function",
    "function": {
        "name": "jump_to_function",
        "description": "Jump to a specific function from the call site worklist to continue the analysis there. This is used after returning from the initial function to investigate its callers.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "The name of the function to jump to. Must be one of the functions from the call site worklist that has not been marked as 'done'."
                }
            },
            "required": ["function_name"]
        }
    }
}

set_conclusion_desc_function = {
    "type": "function",
    "function": {
        "name": "set_conclusion",
        "description": "Sets the final conclusion for an alert analysis. This function should be called at the end of an analysis to provide a definitive classification and the reasoning behind it.",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification of the alert, must be one of 'FP' (False Positive), 'TP' (True Positive), or 'UNCERTAIN'.",
                    "enum": ["FP", "TP", "UNCERTAIN"]
                },
                "reason": {
                    "type": "string",
                    "description": "A detailed explanation for the given classification."
                }
            },
            "required": ["classification", "reason"]
        }
    }
}
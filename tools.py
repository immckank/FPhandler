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

set_conclusion_desc_path = {
    "type": "function",
    "function": {
        "name": "set_conclusion",
        "description": "Set the final classification for a memory handling path at a specific return location. This function analyzes how memory is handled (e.g., null pointer, transferred ownership, freed, leaked) and marks the corresponding return location as analyzed. Use this tool when you have determined the final fate of a memory allocation or pointer along a specific execution path.",
        "parameters": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "description": "The classification type for the memory handling: 'NullPointer' (pointer remains null, no arg needed), 'Transferred with assignment' (ownership transferred, requires arg with transfer location), 'Returned to caller' (memory returned to caller, requires arg with return statement location), 'Handled by callee' (memory explicitly freed, requires arg with free call location), 'Leak' (memory leaked, no arg needed), or 'Unreachable' (code path is unreachable, no arg needed).",
                    "enum": ["NullPointer", "Transferred with assignment", "Returned to caller", "Handled by callee", "Leak", "Unreachable"]
                },
                "source_location": {
                    "type": "string",
                    "description": "The code location related to the classification, required for 'Transferred with assignment', 'Returned to caller', and 'Handled by callee' classifications. Must be in the format 'filename.c:line_number' or 'filename.h:line_number' (e.g., 'crypto/rsa.c:245'). Not required for 'NullPointer', 'Leak', or 'Unreachable'."
                },
                "code_line": {
                    "type": "string",
                    "description": "The code line of the source location, required for 'Transferred', 'Returned', and 'Freed' classifications. Not required for 'NullPointer', 'Leak', or 'Unreachable'."
                },
                "arg": {
                    "type": "string",
                    "description": "Only required when classified as 'Freed' or 'Transferred'. This is used to specify which function was used to release the memory, or to which variable the memory was explicitly transferred."
                },
                "return_location": {
                    "type": "string",
                    "description": "The specific return location being analyzed. This should match one of the return locations in the current analysis context. After setting the conclusion, this return location will be marked as done."
                },
                "reason": {
                    "type": "string",
                    "description": "A detailed explanation for the given classification, including the evidence and reasoning that led to this conclusion."
                }
            },
            "required": ["classification", "return_location", "reason"]
        }
    }
}

create_path_desc_path = {
    "type": "function",
    "function": {
        "name": "create_path",
        "description": "Create a temporary analysis path for the given return location. Call this before recording any path events so that subsequent updates attach to the correct path.",
        "parameters": {
            "type": "object",
            "properties": {
                "return_location": {
                    "type": "string",
                    "description": "The return location this path targets, in the format 'filename.c:line_number'. Must match one of the return locations provided in the current analysis context."
                },
                "description": {
                    "type": "string",
                    "description": "Short description of the path that is stored together with its events."
                },
            },
            "required": ["return_location", "description"]
        }
    }
}

add_path_gep_to_baseobj_desc_path = {
    "type": "function",
    "function": {
        "name": "add_path_gep_to_baseobj",
        "description": "Record a GEP event that transfers ownership to a struct base object and append it to the specified path.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier returned by create_path for the path being augmented."
                },
                "gep_location": {
                    "type": "string",
                    "description": "Source location of the GEP instruction in the format 'filename.c:line_number'."
                },
                "baseobj_name": {
                    "type": "string",
                    "description": "Variable name of the struct base object receiving ownership."
                }
            },
            "required": ["path_id", "gep_location", "baseobj_name"]
        }
    }
}

add_path_gep_to_member_desc_path = {
    "type": "function",
    "function": {
        "name": "add_path_gep_to_member",
        "description": "Record a GEP event that accesses a struct member from a base object and append it to the specified path.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier returned by create_path for the path being augmented."
                },
                "gep_location": {
                    "type": "string",
                    "description": "Source location of the GEP instruction in the format 'filename.c:line_number'."
                },
                "member_name": {
                    "type": "string",
                    "description": "Name of the struct member reached through the GEP."
                }
            },
            "required": ["path_id", "gep_location", "member_name"]
        }
    }
}

complete_path_desc_path = {
    "type": "function",
    "function": {
        "name": "complete_path",
        "description": "Finalize an analysis path by providing its classification and reasoning, marking the path as completed.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "Identifier of the path being finalized."
                },
                "classification": {
                    "type": "string",
                    "description": "Indicates how memory is ultimately handled on this path.",
                    "enum": ["NullPointer", "Transferred with assignment", "Returned to caller", "Handled by callee", "Leak", "Unreachable"]
                },
                "reason": {
                    "type": "string",
                    "description": "Detailed justification for the chosen classification."
                },
                "source_location": {
                    "type": "string",
                    "description": "Required when the classification is 'Transferred with assignment', 'Returned to caller', or 'Handled by callee'. Specifies the related source location in the format 'filename.c:line_number'."
                },
                "code_line": {
                    "type": "string",
                    "description": "The code line corresponding to the source_location when required."
                },
                "arg": {
                    "type": "string",
                    "description": "When applicable, identifies the variable or function involved in the transfer or free."
                }
            },
            "required": ["path_id", "classification", "reason"]
        }
    }
}

query_paths_desc_path = {
    "type": "function",
    "function": {
        "name": "query_paths",
        "description": "Query the temporary store of analysis paths by a specific path identifier. Deleted paths are not returned.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "Identifier of the path to inspect. Returns an error if the path is missing or deleted."
                }
            },
            "required": ["path_id"]
        }
    }
}

delete_path_desc_path = {
    "type": "function",
    "function": {
        "name": "delete_path",
        "description": "Remove an in-progress analysis path when it was created by mistake. Completed paths cannot be deleted.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier of the path to delete."
                }
            },
            "required": ["path_id"]
        }
    }
}
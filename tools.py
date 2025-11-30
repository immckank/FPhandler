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

read_ctag_symbol_desc_free = {
    "type": "function",
    "function": {
        "name": "read_ctag_symbol",
        "description": "Look up symbol locations using the pre-generated ctags index.",
        "parameters": {
            "type": "object",
            "properties": {
                "symbol_name": {
                    "type": "string",
                    "description": "Identifier to search for (function, variable, macro, etc.)."
                }
            },
            "required": ["symbol_name"]
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
                    "description": "The classification type for the memory handling: 'NullPointer' (pointer remains null, no arg needed), 'Transferred' (ownership transferred, requires arg with transfer location), 'Returned to caller' (memory returned to caller, requires arg with return statement location), 'Handled by callee' (memory explicitly freed, requires arg with free call location), 'Leak' (memory leaked, no arg needed), or 'Unreachable' (code path is unreachable, no arg needed).",
                    "enum": ["NullPointer", "Transferred", "Returned to caller", "Handled by callee", "Leak", "Unreachable"]
                },
                "source_location": {
                    "type": "string",
                    "description": "The code location related to the classification, required for 'Transferred', 'Returned to caller', and 'Handled by callee' classifications. Must be in the format 'filename.c:line_number' or 'filename.h:line_number' (e.g., 'crypto/rsa.c:245'). Not required for 'NullPointer', 'Leak', or 'Unreachable'."
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
                "depends_on": {
                    "type": ["string", "array"],
                    "items": {"type": "string"},
                    "description": "Optional dependency path id or list of ids. Defaults to the parent analysis path id when omitted."
                },
            },
            "required": ["return_location", "description"]
        }
    }
}

describe_return_locations_desc_path = {
    "type": "function",
    "function": {
        "name": "describe_return_locations",
        "description": "Summarize each return location with multiple potential paths, including code context and current completion status, to guide further analysis within the function.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
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
                    "type": ["string", "object"],
                    "description": "Either a string classification or a unified decision JSON. String enum: ['NullPointer','Unreachable','Handled by callee','Returned as Return value','Returned as Pointer parameter','Leak']. When using unified JSON, provide an object: { category: 'HandledByCallee'|'ReturnedAsReturnValue'|'ReturnedAsPointerParameter'|'NullPointer'|'Unreachable'|'Leaked', params?: {...} }. For 'HandledByCallee', params can include: { source_location, callee_function_name, arg_index? }. For 'ReturnedAsPointerParameter', params can include: { param_index } (0-based index).",
                    "enum": ["NullPointer", "Unreachable", "Handled by callee", "Returned as Return value", "Returned as Pointer parameter", "Leak"]
                },
                "reason": {
                    "type": "string",
                    "description": "Detailed justification for the chosen classification."
                },
                "conditions": {
                    "type": "string",
                    "description": "Summary of the conditions that must be met for the path to be valid."
                },
                "source_location": {
                    "type": "string",
                    "description": "Required when classification is 'Handled by callee'. Specifies the function call site source location in the format 'filename.c:line_number'."
                },
                "code_line": {
                    "type": "string",
                    "description": "Required when classification is 'Handled by callee'. The actual code line at the source_location where the function call occurs."
                },
                "callee_function_name": {
                    "type": "string",
                    "description": "Required when classification is 'Handled by callee'. The name of the function that handles/releases the memory (e.g., 'free', 'fclose')."
                },
                "arg_index": {
                    "type": "integer",
                    "description": "For 'Handled by callee': optional 0-based index of the argument passed to the callee function (can be extracted from code_line if not provided). For 'Returned as Pointer parameter': required 0-based index of the parameter that receives the pointer."
                }
            },
            "required": ["path_id", "classification", "reason", "conditions"]
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

# Path builder agent tool descriptions
add_state_node_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "add_state_node",
        "description": "Add a memory state node to the currently active path. Path identifiers are managed automatically; you never need to specify them. Each node represents a memory state operation (e.g., Transferred, HandledByCallee, Deallocated). After adding a node, you should immediately add a transition edge using add_transition_edge to record the conditions for reaching this node.",
        "parameters": {
            "type": "object",
            "properties": {
                "node_type": {
                    "type": "string",
                    "description": "The type of the node. Predefined types: 'Transferred' (memory ownership transfer), 'HandledByCallee' (passed to callee function), 'Deallocated' (memory freed), 'ReturnedAsReturnValue', 'ReturnedAsPointerParameter', 'Leak', 'NullPointer', 'Unreachable'. You can also use custom node types created via create_custom_node_type.",
                    "enum": ["Transferred", "HandledByCallee", "Deallocated", "ReturnedAsReturnValue", "ReturnedAsPointerParameter", "Leak", "NullPointer", "Unreachable"]
                },
                "location": {
                    "type": "string",
                    "description": "Source code location in the format 'filename.c:line_number'."
                },
                "code_line": {
                    "type": "string",
                    "description": "The code line at the location."
                },
                "source_object": {
                    "type": "string",
                    "description": "Source object (e.g., '*data'). Required for Transferred type. Can be None for other types."
                },
                "target_object": {
                    "type": "string",
                    "description": "Target object (e.g., '*p'). Required for Transferred type. Can be None for other types."
                },
                "metadata": {
                    "type": "object",
                    "description": "Additional metadata (e.g., function name, argument index). Optional."
                }
            },
            "required": ["node_type", "location", "code_line"]
        }
    }
}

add_transition_edge_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "add_transition_edge",
        "description": "Add a transition edge between two nodes on the currently active path. Path identifiers are handled by the system. This is CRITICAL - every state transition must have an edge that records the conditions for the transition. The edge represents the control flow conditions (if/while/for conditions) that must be satisfied to move from one state to another.",
        "parameters": {
            "type": "object",
            "properties": {
                "from_node_id": {
                    "type": "string",
                    "description": "The node_id of the source node."
                },
                "to_node_id": {
                    "type": "string",
                    "description": "The node_id of the target node."
                },
                "conditions": {
                    "type": "string",
                    "description": "The conditions that must be satisfied for this transition (e.g., 'if (ptr != NULL)', 'while (i < n)', 'always true'). This is the key information for the edge."
                },
                "location": {
                    "type": "string",
                    "description": "Source code location where the condition is evaluated, in the format 'filename.c:line_number'."
                },
                "code_line": {
                    "type": "string",
                    "description": "The code line containing the condition."
                },
                "description": {
                    "type": "string",
                    "description": "Natural language description of the condition (e.g., 'pointer is not null', 'loop continues while i < n')."
                }
            },
            "required": ["from_node_id", "to_node_id", "conditions", "location", "code_line", "description"]
        }
    }
}

complete_path_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "complete_path",
        "description": "Complete the currently active path by specifying its termination state. The path must end with a valid termination type. The system will validate the path and automatically move to the next one.",
        "parameters": {
            "type": "object",
            "properties": {
                "termination_type": {
                    "type": "string",
                    "description": "The termination type of the path. Must be one of: 'Deallocated' (memory freed), 'Leak' (memory leaked), 'ReturnedAsReturnValue' (returned as return value), 'ReturnedAsPointerParameter' (returned as pointer parameter), 'NullPointer' (pointer is null), 'Unreachable' (path is unreachable).",
                    "enum": ["Deallocated", "Leak", "ReturnedAsReturnValue", "ReturnedAsPointerParameter", "NullPointer", "Unreachable"]
                },
                "reason": {
                    "type": "string",
                    "description": "Detailed explanation for the termination type."
                }
            },
            "required": ["termination_type", "reason"]
        }
    }
}

create_custom_node_type_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "create_custom_node_type",
        "description": "Create a custom node type if the predefined types are not sufficient. You should provide a clear description of when to use this type.",
        "parameters": {
            "type": "object",
            "properties": {
                "type_name": {
                    "type": "string",
                    "description": "The name of the custom node type."
                },
                "description": {
                    "type": "string",
                    "description": "Description of when and how to use this node type."
                }
            },
            "required": ["type_name", "description"]
        }
    }
}

query_path_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "query_path",
        "description": "Query the current state of a path, including all nodes and edges.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier of the path to query."
                }
            },
            "required": ["path_id"]
        }
    }
}

merge_paths_desc_path_builder = {
    "type": "function",
    "function": {
        "name": "merge_paths",
        "description": "Merge multiple similar paths. Paths are considered similar if they have the same node type sequence, the same edge condition sequence, and the same termination type. Only completed paths can be merged.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of path identifiers to merge. Must have at least 2 paths."
                },
                "description": {
                    "type": "string",
                    "description": "Description of the merged path. Optional."
                }
            },
            "required": ["path_ids"]
        }
    }
}

# Function node builder agent tool descriptions
add_value_flow_node_desc_node_builder = {
    "type": "function",
    "function": {
        "name": "add_value_flow_node",
        "description": "Add a critical value flow operation node. This tool is used to identify and record key value flow operations within a function for memory leak detection. You should filter out non-critical operations that are not important for memory leak analysis.",
        "parameters": {
            "type": "object",
            "properties": {
                "node_type": {
                    "type": "string",
                    "description": "The type of the value flow node. Must be one of: 'Transferred' (value transfer between variables), 'HandledByCallee' (memory handled by callee function), 'Deallocated' (memory freed), 'ReturnedAsReturnValue' (returned as return value), 'ReturnedAsPointerParameter' (returned via pointer parameter), 'Leak' (memory leak occurs), 'NullPointer' (pointer is null).",
                    "enum": ["Transferred", "HandledByCallee", "Deallocated", "ReturnedAsReturnValue", "ReturnedAsPointerParameter", "Leak", "NullPointer"]
                },
                "location": {
                    "type": "string",
                    "description": "Source code location where the operation occurs, in the format 'filename.c:line_number'."
                },
                "code_line": {
                    "type": "string",
                    "description": "The code line at the location."
                },
                "source_object": {
                    "type": "string",
                    "description": "Source variable name (required for Transferred type). The variable from which memory is transferred."
                },
                "target_object": {
                    "type": "string",
                    "description": "Target variable name (required for Transferred type). The variable to which memory is transferred."
                },
                "callee_function_name": {
                    "type": "string",
                    "description": "Name of the callee function (required for HandledByCallee type)."
                },
                "param_name": {
                    "type": "string",
                    "description": "Parameter name (required for HandledByCallee, Deallocated, ReturnedAsPointerParameter types). For HandledByCallee: the parameter name passed to the callee. For Deallocated: the parameter name passed to free/deallocation function. For ReturnedAsPointerParameter: the parameter name that receives the memory."
                },
                "return_location": {
                    "type": "string",
                    "description": "Return location in format 'filename.c:line_number' (required for Leak and NullPointer types). For Leak: the return location after which the variable becomes unreachable. For NullPointer: the return location before which memory allocation may fail and remain null."
                }
            },
            "required": ["node_type", "location", "code_line"]
        }
    }
}

# FunctionPathBuilderAgent tool descriptions
complete_path_desc_function_path_builder = {
    "type": "function",
    "function": {
        "name": "complete_path",
        "description": "Complete a path analysis by classifying its memory state. For classifications that require key_operation (HandledByCallee, Deallocated, ReturnedAsReturnValue, ReturnedAsPointerParameter), you must specify a key_operation_source_location that matches a non-branch node in the path. For HandledByCallee and Deallocated classifications, you must also provide the callee_function_name, which must appear in the key_operation_code_line. For Leak, NullPointer, and Unreachable classifications, key_operation is not required.",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier of the path to complete (e.g., 'path_1', 'path_2')."
                },
                "classification": {
                    "type": "string",
                    "description": "The memory state classification for the path. Must be one of: 'HandledByCallee' (memory handled by callee, requires key_operation and callee_function_name), 'Deallocated' (memory freed, requires key_operation and callee_function_name), 'ReturnedAsReturnValue' (returned as return value, requires key_operation), 'ReturnedAsPointerParameter' (returned as pointer parameter, requires key_operation), 'Leak' (memory leak, no key_operation needed), 'NullPointer' (pointer is null, no key_operation needed), 'Unreachable' (path is unreachable, no key_operation needed).",
                    "enum": ["HandledByCallee", "Deallocated", "ReturnedAsReturnValue", "ReturnedAsPointerParameter", "Leak", "NullPointer", "Unreachable"]
                },
                "reason": {
                    "type": "string",
                    "description": "Detailed explanation for the classification, including evidence and reasoning."
                },
                "key_operation_source_location": {
                    "type": "string",
                    "description": "Source location of the key operation in format 'filename.c:line_number' (required for HandledByCallee, Deallocated, ReturnedAsReturnValue, ReturnedAsPointerParameter). This location must match a non-branch node in the path's path_node_list. Not required for Leak, NullPointer, or Unreachable."
                },
                "key_operation_code_line": {
                    "type": "string",
                    "description": "The code line at the key_operation_source_location (required for HandledByCallee, Deallocated, ReturnedAsReturnValue, ReturnedAsPointerParameter). For HandledByCallee and Deallocated, this code line must contain the callee_function_name. Not required for Leak, NullPointer, or Unreachable."
                },
                "callee_function_name": {
                    "type": "string",
                    "description": "The name of the function that handles/releases the memory (required for HandledByCallee and Deallocated classifications). This function name must appear in the key_operation_code_line. Examples: 'free', 'fclose', 'close', etc. Not required for other classifications."
                }
            },
            "required": ["path_id", "classification", "reason"]
        }
    }
}

# FunctionPathCheckerAgent tool descriptions
check_path_desc_function_path_checker = {
    "type": "function",
    "function": {
        "name": "check_path",
        "description": "Check the feasibility of a path by analyzing its branch constraints for conflicts. This tool validates whether a path is executable by checking if all branch conditions along the path are consistent and satisfiable. Use this after analyzing the branch constraints to classify the path as either feasible (path can be executed) or not feasible (path has conflicting constraints or is unreachable).",
        "parameters": {
            "type": "object",
            "properties": {
                "path_id": {
                    "type": "string",
                    "description": "The identifier of the path to check (e.g., '1', '2', 'path_1')."
                },
                "feasibility": {
                    "type": "string",
                    "description": "The feasibility classification for the path. Must be one of: 'feasible' (the path can be executed, all constraints are consistent) or 'not feasible' (the path has conflicting constraints or is unreachable due to impossible conditions).",
                    "enum": ["feasible", "not feasible"]
                },
                "reason": {
                    "type": "string",
                    "description": "Detailed explanation for the feasibility classification. For 'feasible' paths, explain why the constraints are consistent. For 'not feasible' paths, clearly identify the conflicting constraints or impossible conditions that make the path unreachable. Include specific branch conditions and their locations in your explanation."
                }
            },
            "required": ["path_id", "feasibility", "reason"]
        }
    }
}

# Tool description for get_local_var_type function
get_local_var_type_desc = {
    "type": "function",
    "function": {
        "name": "get_local_var_type",
        "description": "Retrieves the type and definition information for a local variable within a specific function. This tool parses the function's source code using tree-sitter to locate the variable declaration and extract its type information, location, and the actual code line where it is declared.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "The name of the function containing the local variable. Must be a non-empty string and match an existing function in the codebase."
                },
                "var_name": {
                    "type": "string",
                    "description": "The name of the local variable to look up. Must be a non-empty string and must be declared within the specified function."
                }
            },
            "required": ["function_name", "var_name"]
        }
    }
}

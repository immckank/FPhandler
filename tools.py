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
                "reason": { "type": "string", "description": "A detailed explanation for the given classification."},
                "semantic_candidates": {
                    "type": "array",
                    "description": "Only reusable, code-backed semantic facts. Return [] when none are justified.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": ["initializer", "memory_transfer", "allocator", "deallocator", "resource_open", "resource_close", "ownership_transfer", "heap_object_summary", "domain_hint"]
                            },
                            "function": {"type": "string"},
                            "match": {"type": "string", "enum": ["exact", "substring"]},
                            "effect": {"type": "string"},
                            "target_arg": {"type": "integer", "minimum": -1},
                            "source_arg": {"type": "integer", "minimum": -1},
                            "length_arg": {"type": "integer", "minimum": -1},
                            "field_path": {"type": "string"},
                            "pair": {"type": "string"},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                            "reason": {"type": "string"}
                        },
                        "required": ["kind", "function", "confidence", "reason"]
                    }
                }
            },
            "required": ["classification", "reason", "semantic_candidates"]
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

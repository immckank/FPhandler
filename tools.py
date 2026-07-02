# Free analyzer tool descriptions
set_conclusion_desc_free = {
    "type": "function",
    "function": {
        "name": "set_conclusion",
        "description": (
            "Sets one conclusion for one or more alert IDs. IDs in one call share "
            "the same classification and reason. Call it repeatedly for groups with "
            "different conclusions; analysis ends after every current-batch ID is covered."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "alert_ids": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                    "description": "One or more alert IDs covered by this conclusion.",
                },
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
            "required": ["alert_ids", "classification", "reason", "semantic_candidates"]
        }
    }
}

dump_source_snippet_desc_free = {
    "type": "function",
    "function": {
        "name": "dump_source_snippet",
        "description": (
            "Dumps source lines. Copy a path from alert evidence or a previous tool "
            "result; source/mount prefixes and minor directory mismatches are resolved."
        ),
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
        "description": "Dumps one source line using a path from alert evidence or another tool.",
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
        "description": "Finds the function containing an exact location copied from alert evidence.",
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
        "description": (
            "Finds a function body by its exact IR/mangled name. Do not pass class "
            "names, macro names, or guessed demangled fragments."
        ),
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

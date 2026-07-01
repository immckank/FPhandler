from abc import ABC, abstractmethod
from openai import OpenAI

import json
import os
import logging
import time

import memory_defect

from analysis_operators import *
from config import *
from utils import *
from prompts import *
import re
from batch_conclusions import BatchConclusions
from tools import (
    set_conclusion_desc_free,
    set_batch_conclusions_desc_free,
    dump_source_snippet_desc_free,
    dump_source_line_desc_free,
    find_current_function_desc_free,
    find_function_body_desc_free,
    find_callers_desc_free
)

class FreeAnalysisModel(ABC):
    def __init__(self):
        self.analysis_logger = setup_logger(log_type="analysis") 
        self.result_logger = setup_logger(log_type="result")
        self.tool_functions = {
            "set_conclusion": set_conclusion,
            "dump_source_snippet": dump_source_snippet,
            "dump_source_line": dump_source_line,
            "find_callee": find_callee,
            "find_current_function": find_current_function,
            "find_callers": find_callers,
            "find_function_body": find_function_body,
            "get_path_cond_func_": get_path_cond_func_,
        }   
        self.last_result = None
        self.last_results = {}
        pass
    
    def send_message(self, messages, tools=""):
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    tools=tools
                )
                if response and getattr(response, "choices", None):
                    return response.choices[0].message
                self.analysis_logger.error(
                    "LLM returned empty response/choices (attempt %d/%d)",
                    attempt,
                    max_attempts,
                )
            except Exception as e:
                self.analysis_logger.error(
                    "LLM request failed (attempt %d/%d): %s",
                    attempt,
                    max_attempts,
                    str(e),
                )
            if attempt < max_attempts:
                time.sleep(1.5 * attempt)
        return None
    
    
    @abstractmethod
    def responseToAlter(self, alter_prompt, user_prompt=""):
        pass

    def responseForAlter(self, alter: memory_defect.MemoryDefect):
        """
        返回 True 表示模型已调用 set_conclusion 并得到成功结论；
        run.py 仅在此时把 alter.get_source_loc() 规范化为 fl:ln 写入去重文件。
        去重键由各缺陷类构造时的 source_loc（警报发生位置）决定，与是否 MemoryLeak 无关。
        """
        self.last_result = None
        if hasattr(alter, "document"):
            conclusion_id = alter.document.data["alert_id"]
        else:
            source = alter.get_source_loc() if hasattr(alter, "get_source_loc") else None
            conclusion_id = f"legacy:{source or getattr(alter, 'source_location', 'unknown')}"
        allowed_tools = [
            set_conclusion_desc_free, dump_source_snippet_desc_free, dump_source_line_desc_free, 
            find_current_function_desc_free, find_function_body_desc_free, find_callers_desc_free
        ]
        project_prompt = f"You are now working for project {PROJECT_LABEL}. "
        project_prompt += PROJECT_DESC + "\n"        
        self.analysis_logger.info(f"Prompt: {alter.to_prompt()}")
        self.result_logger.info(f"\nPrompt: {alter.to_prompt()}\n")
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT},
            {
                "role": "user",
                "content": (
                    alter.to_prompt()
                    + "\n"
                    + project_prompt
                    + f"\nCall set_conclusion with alert_ids=[{conclusion_id!r}]."
                ),
            }
        ]
        # find_current_function 在失败时返回 {"error": ...}；优先用结构化 fl/ln 发后端
        func_info = find_current_function(
            alter.get_source_loc() if hasattr(alter, "get_source_loc") and alter.get_source_loc() else alter.source_location
        )
        if isinstance(func_info, dict) and func_info.get("error"):
            alter_function_name = "unknown"
        else:
            alter_function_name = (
                func_info.get("function_name") if isinstance(func_info, dict) else None
            ) or "unknown"
        response = self.send_message(messages, allowed_tools)
        if response is None:
            err = {
                "classification": "UNCERTAIN",
                "reason": "LLM returned empty/invalid response before any tool call.",
                "function_name": alter_function_name,
            }
            self.analysis_logger.error(f"Model response is None: {err}")
            self.result_logger.info(f"{err}")
            return False
        response_content = getattr(response, "content", None) or ""
        self.analysis_logger.info(f"Model response: {response_content}")
        messages.append(response)
        while getattr(response, "tool_calls", None):
            for tool_call in response.tool_calls:
                tool_function_name = tool_call.function.name
                try:
                    tool_arguments = safe_load_json(tool_call.function.arguments)
                except Exception as e:
                    # Log and respond with an error so the model can recover
                    self.analysis_logger.error(f"Failed to parse tool arguments: {e}")
                    function_response = json.dumps({"error": f"failed to parse arguments: {str(e)}"})
                    messages.append(
                        {
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "content": function_response,
                        }
                    )
                    # ask the model for next action by continuing the loop
                    continue
                self.analysis_logger.info(f"Calling tool: {tool_function_name} with args: {tool_arguments}")
                if tool_function_name == "set_conclusion":
                    function_response = set_conclusion(**tool_arguments)
                    if "error" in function_response:
                        messages.append({
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "content": json.dumps(function_response),
                        })
                        continue
                    if function_response.get("alert_ids") != [conclusion_id]:
                        function_response = {
                            "error": "alert_ids must exactly match the current alert",
                            "expected": [conclusion_id],
                        }
                        messages.append({
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "content": json.dumps(function_response),
                        })
                        continue
                    function_response["function_name"] = alter_function_name
                    self.last_result = function_response
                    self.analysis_logger.info(f"Tool response: {function_response}")
                    self.result_logger.info(f"{function_response}")
                    return True
                elif tool_function_name in self.tool_functions:
                    function_response = self.tool_functions[tool_function_name](**tool_arguments)
                else:
                    self.analysis_logger.error(f"Unknown tool call: {tool_function_name}")
                    function_response = f"Error: Tool '{tool_function_name}' not found."
                # Convert response to JSON string if it's not already a string
                if not isinstance(function_response, str):
                    function_response = json.dumps(function_response)
                
                self.analysis_logger.info(f"Tool response: {function_response}")   
                messages.append(
                    {
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "content": function_response,
                    }
                )
            # Send the tool responses back to the model
            response = self.send_message(messages, allowed_tools)
            if response is None:
                err = {
                    "classification": "UNCERTAIN",
                    "reason": "LLM returned empty/invalid response after tool call.",
                    "function_name": alter_function_name,
                }
                self.analysis_logger.error(f"Model response is None: {err}")
                self.result_logger.info(f"{err}")
                return False
            response_content = getattr(response, "content", None) or ""
            self.analysis_logger.info(f"Model response: {response_content}")
            messages.append(response)
        if response_content.strip():
            self.result_logger.info(
                "{'classification': 'UNCERTAIN', 'reason': 'Model returned text only without tool call.', 'raw_response': %s, 'function_name': %r}",
                repr(response_content),
                alter_function_name,
            )
        return False

    def responseForAlerts(self, alerts, batch_id="B0001"):
        """Analyze alerts until every batch-local ID has a conclusion."""
        self.last_results = {}
        if not alerts:
            return True
        id_map = {
            f"{batch_id}-A{index:02d}": alert.document.data["alert_id"]
            for index, alert in enumerate(alerts, 1)
        }
        state = BatchConclusions(id_map)
        prompt = (
            f"Analyze batch {batch_id}. Every alert must be classified before you finish. "
            "Call set_batch_conclusions with one or more conclusions. Each conclusion "
            "must contain one or more alert_ids; group IDs only when the evidence supports "
            "the same classification and reason. You may call the tool multiple times. "
            "Use only the short IDs shown below.\n\n"
            + "\n\n--- NEXT ALERT ---\n\n".join(
                alert.to_prompt(short_id)
                for short_id, alert in zip(id_map, alerts)
            )
        )
        tools = [
            set_batch_conclusions_desc_free,
            dump_source_snippet_desc_free,
            dump_source_line_desc_free,
            find_current_function_desc_free,
            find_function_body_desc_free,
            find_callers_desc_free,
        ]
        messages = [
            {"role": "system", "content": SYS_PROMPT + ASSUMPTION_PROMPT},
            {"role": "user", "content": prompt},
        ]
        for _ in range(12):
            response = self.send_message(messages, tools)
            if response is None:
                return False
            messages.append(response)
            calls = getattr(response, "tool_calls", None) or []
            if not calls:
                messages.append({
                    "role": "user",
                    "content": (
                        "The batch is not complete. Call set_batch_conclusions for "
                        f"these remaining IDs: {state.missing}"
                    ),
                })
                continue
            for call in calls:
                name = call.function.name
                try:
                    arguments = safe_load_json(call.function.arguments)
                except Exception as error:
                    value = {"error": f"invalid tool arguments: {error}"}
                else:
                    if name == "set_batch_conclusions":
                        value = state.add(arguments.get("results"))
                        self.analysis_logger.info(
                            "Batch %s conclusion progress: %s", batch_id, value
                        )
                        self.result_logger.info(
                            "Batch %s conclusion progress: %s", batch_id, value
                        )
                        if state.complete:
                            self.last_results = state.canonical_results()
                            return True
                    elif name in self.tool_functions:
                        value = self.tool_functions[name](**arguments)
                    else:
                        value = {"error": f"unknown tool: {name}"}
                messages.append({
                    "tool_call_id": call.id,
                    "role": "tool",
                    "content": value if isinstance(value, str) else json.dumps(value),
                })
        return False

class DeepSeekFreeAnalyzer(FreeAnalysisModel):
    def __init__(self, model_name="deepseek-chat"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
            
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter: memory_defect.MemoryDefect):
        return super().responseForAlter(alter)

class QwenFreeAnalyzer(FreeAnalysisModel):
    def __init__(self, model_name="qwen3-max"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("QWEN_API_KEY"),
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        
    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None
    
    def responseForAlter(self, alter: memory_defect.MemoryDefect):
        return super().responseForAlter(alter)

class ExampleFreeAnalyzer(FreeAnalysisModel):
    """Template analyzer: copy and adjust base_url / model_name / api key env for a new provider."""

    def __init__(self, model_name="example-model"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("EXAMPLE_KEY"),
            base_url="exampleurl",
        )

    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None

    def responseForAlter(self, alter: memory_defect.MemoryDefect):
        return super().responseForAlter(alter)


class HWFreeAnalyzer(FreeAnalysisModel):
    """OpenAI-compatible analyzer using HW_KEY and model auto."""

    def __init__(self, model_name="auto"):
        super().__init__()
        self.model_name = model_name
        self.client = OpenAI(
            api_key=os.environ.get("HW_KEY"),
            base_url="exampleurl",
        )

    def responseToAlter(self, alter_prompt, user_prompt=""):
        return None

    def responseForAlter(self, alter: memory_defect.MemoryDefect):
        return super().responseForAlter(alter)


def create_analyzer():
    """Create the free-form analyzer for the configured LLM_TYPE."""
    if LLM_TYPE == "DeepSeek":
        return DeepSeekFreeAnalyzer()
    if LLM_TYPE == "Qwen":
        return QwenFreeAnalyzer()
    if LLM_TYPE == "Example":
        return ExampleFreeAnalyzer()
    if LLM_TYPE == "HW":
        return HWFreeAnalyzer()
    raise ValueError(f"Unknown LLM type: {LLM_TYPE}")

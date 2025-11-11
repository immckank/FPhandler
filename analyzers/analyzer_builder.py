from config import *
from typing import Optional
from .free_analyzer import GeminiFreeAnalyzer, DeepSeekFreeAnalyzer, QwenFreeAnalyzer
from .func_analyzer import DeepSeekFunctionAnalyzer, QwenFunctionAnalyzer
from .path_analyzer import DeepSeekPathAnalyzer, QwenPathAnalyzer

def create_analyzer():
    """Factory function to create an analyzer based on its type."""

    if ANALYZER_TYPE == "free":
        if LLM_TYPE == "Gemini":
            return GeminiFreeAnalyzer()
        elif LLM_TYPE == "DeepSeek":
            return DeepSeekFreeAnalyzer()
        elif LLM_TYPE == "Qwen":
            return QwenFreeAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    elif ANALYZER_TYPE == "function":
        if LLM_TYPE == "DeepSeek":
            return DeepSeekFunctionAnalyzer()
        if LLM_TYPE == "Qwen":
            return QwenFunctionAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    elif ANALYZER_TYPE == "path":
        if LLM_TYPE == "DeepSeek":
            return DeepSeekPathAnalyzer()
        if LLM_TYPE == "Qwen":
            return QwenPathAnalyzer()
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    else:
        raise ValueError(f"Unknown analyzer type: {ANALYZER_TYPE}")
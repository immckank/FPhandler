import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from google import genai
from google.genai import types
from abc import ABC, abstractmethod
from pydantic import BaseModel
from openai import OpenAI

import json
import logging

import memory_defect

from analysis_operators import *
from config import *
from utils import *
from prompts import *
import re
from func_analyzer_layered import (
    DeepSeekFunctionAnalyzer,
    QwenFunctionAnalyzer
)
from path_analyzer_layered import (
    DeepSeekPathAnalyzer,
    QwenPathAnalyzer
)


def create_analyzer(analyzer_type: str, result_logger, analysis_logger):
    """Factory function to create an analyzer based on its type."""
    if analyzer_type == "function":
        if LLM_TYPE == "DeepSeek":
            analyzer = DeepSeekFunctionAnalyzer(result_logger, analysis_logger)
        elif LLM_TYPE == "Qwen":
            analyzer = QwenFunctionAnalyzer(result_logger, analysis_logger)
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    elif analyzer_type == "path":
        if LLM_TYPE == "DeepSeek":
            analyzer = DeepSeekPathAnalyzer(result_logger, analysis_logger)
        elif LLM_TYPE == "Qwen":
            analyzer = QwenPathAnalyzer(result_logger, analysis_logger)
        else:
            raise ValueError(f"Unknown LLM type: {LLM_TYPE}")
    else:
        raise ValueError(f"Unknown analyzer type: {analyzer_type}")
    return analyzer
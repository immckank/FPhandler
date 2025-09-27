from google import genai
from google.genai import types

from pydantic import BaseModel

from analysis_operators import dump_source_snippet
from analysis_operators import dump_source_line
from analysis_operators import find_callee
from analysis_operators import find_current_function
from analysis_operators import find_callers


class judgeResult(BaseModel):
    classification: str
    reasoning: str

SYS_PROMPT = """
You are a software security researcher tasked with classifying SAST alerts on C code.
Each alert must be classified as one of: TP (true positive): the code violates the guidance provided by the user; FP (false positive): the code follows the guidance; UNCERTAIN: there isn't enough information to decide. 
Each user input will include: the bug type, source file name and line number of the potential bug, the alert message. 
Guidelines: Focus only on the specified bug type and location. Don't speculate about future code changes. Think step by step. Your analysis must be based on the source code.
"""

def resposeToAlter(Alter_prompt, user_prompt=""):
    config = types.GenerateContentConfig(
        system_instruction=SYS_PROMPT,
        response_schema=judgeResult,
        response_mime_type="application/json",
    )
    client = genai.Client()
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=Alter_prompt + "\n" + user_prompt,
        config=config
    )
    return response.text
    
def responseForAlter(Alter_prompt, user_prompt="", allowed_tools = []):
    config = types.GenerateContentConfig(
        system_instruction=SYS_PROMPT,
        response_schema=judgeResult,
        response_mime_type="application/json",
        tools = allowed_tools
    )
    client = genai.Client()
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=Alter_prompt + "\n" + user_prompt,
        config=config
    )
    return response.text
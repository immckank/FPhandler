import os
import subprocess
import logging
import sys
import json
import re
from utils import *
from typing import List, Dict, Any, Optional, Set

from command_caller import CommandCaller

import config

PUT_ROOT_PATH = config.PUT_ROOT_PATH
PROJECT_NAME = config.PROJECT_NAME
PUT_NAME = config.PUT_NAME

'''
system function
'''

def set_conclusion(classification: str, reason: str) -> Dict[str, str]:
    """Sets the final conclusion for an alert analysis.

    This function is intended to be called at the end of an analysis to provide a definitive classification and the reasoning behind it.

    Args:
        classification: The classification of the alert, must be one of "FP"
                        (False Positive), "TP" (True Positive), or "UNCERTAIN".
        reason: Summary a detailed explanation for the given classification.

    Returns:
        If the input is invalid, it returns a dictionary with an error message.
    """
    # check if classification in [FP, TP, UNCERTAIN]
    if classification not in ["FP", "TP", "UNCERTAIN"]:
        message = {"error" : "classification must be one of [FP, TP, UNCERTAIN]"}
        return message
    # reason != none
    if reason is None:
        message = {"error" : "reason must not be none"}
        return message
    message = {"classification" : classification, "reason" : reason}
    return message

    
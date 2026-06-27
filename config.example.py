import os

# 复制为 config.py 后按需修改，或直接使用 script/<object>/run_*.py 入口。

_FPH_ROOT = os.path.abspath(os.path.dirname(__file__))
_WORKSPACE = os.path.abspath(os.path.join(_FPH_ROOT, ".."))

PROJECT_ROOT = "/path/to/project/source"

LINKED_BC_DIR = "/path/to/linked_bc_dir"
BITCODE_PATH = ""

SAR_PATH = "/path/to/xxx.txt"
SAR_BATCH_DIRS = []
SAR_BATCH_DIR = ""

SLICE_DIR = ""

RUN_LOG_STEM = None
RUN_SESSION_TIME_STR = None

PROJECT_LABEL = "my-project"
PROJECT_DESC = ""

RES_ROOT_PATH = "RES"
ANALYZED_LOCATIONS_FILE = os.path.join(RES_ROOT_PATH, "analyzed_locations.txt")

LLM_TYPE = "DeepSeek"  # DeepSeek / Qwen / Gemini / Example

GRAPH_READER_DOCKER_IMAGE = "svf-llvm21"

SOURCE_PATH_INCLUDE = []

EXPERIMENT_FOCUS_LOCATIONS = []
EXPERIMENT_FOCUS_TOLERANCE = 3

EXPERIMENT_MAX_ALERTS_PER_FILE = 0

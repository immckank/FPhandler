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

# 默认开启：按 slice JSON 合并 uninit / 按 free 点合并 UAF，减少 LLM 调用次数。
# uninit 合并需同名 *_slices.json（或 SLICE_DIR）；缺失时自动回退为逐条 SAR 告警。
UNINIT_GROUP_FROM_SLICES = True
UNINIT_GROUP_MAX_SAMPLE_SLICES = 5
UAF_CLUSTER_BY_FREE_LOCATION = True

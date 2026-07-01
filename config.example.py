import os

# 复制为 config.py 后按需修改，或使用全局管线 script/config.py。
#
#   cp script/config.env.example script/config.env
#   ./script/run_pipeline.sh
#   # 或
#   source script/lib/common.sh && load_config
#   cd FPhandler && python3 run.py --config ../script/config.py

_FPH_ROOT = os.path.abspath(os.path.dirname(__file__))
_WORKSPACE = os.path.abspath(os.path.join(_FPH_ROOT, ".."))

PROJECT_ROOT = "/path/to/project/source"
OUTPUT_DIR = "/path/to/saber/output"

BITCODE_PATH = ""
ALERT_DIR = os.path.join(OUTPUT_DIR, "alerts")

RUN_LOG_STEM = None
RUN_SESSION_TIME_STR = None

PROJECT_LABEL = "my-project"
PROJECT_DESC = ""

RES_ROOT_PATH = os.path.join(OUTPUT_DIR, "fphandler")

LLM_TYPE = "DeepSeek"  # DeepSeek / Qwen / Example / HW
ALERT_BATCH_SIZE = 5

# Docker 模式下 graph-reader 与 saber 共用 SVF_DOCKER_IMAGE（由 script/config.env 导出）
SVF_DOCKER_IMAGE = ""

STATS_ONLY = False

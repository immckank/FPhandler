import os

# 路径配置：源码根、bitcode（显式或按 SAR 在 LINKED_BC_DIR 同名解析）、SAR
# 项目源码根目录（os.walk / 相对路径基准）
PROJECT_ROOT = "/data/OpenHarmony-4.0-Release"
# PROJECT_ROOT = "/data/PUT/openssl-67dc995e"

# bitcode：非空时为固定路径；空字符串则在 LINKED_BC_DIR 下按当前 SAR 基名（无扩展名）+ ".bc" 自动解析
LINKED_BC_DIR = "/data/linked"
BITCODE_PATH = ""
# BITCODE_PATH = "/data/OpenHarmony-4.1-Release.bc"

# SAR 完整路径（无批处理目录或目录无效时作为唯一输入）
SAR_PATH = ""
# SAR_PATH = "SAR/openssl-67dc995e.txt"

# 批处理：SAR_BATCH_DIRS 非空时优先，按列表顺序依次扫各目录下全部 .txt；否则用 SAR_BATCH_DIR 单目录
SAR_BATCH_DIRS = [
    "SAR/oh-4.0-release-uninit/foundation_communication",
]
# SAR_BATCH_DIRS = []

SAR_BATCH_DIR = ""
# SAR_BATCH_DIR = "SAR/oh-4.0-release-leak/base_security"

# run.py 批处理时可覆盖，用于统一日志文件名前缀与时间戳
RUN_LOG_STEM = None
RUN_SESSION_TIME_STR = None

# LLM 提示用展示名
PROJECT_LABEL = "OpenHarmony-4.0-Release"
# PROJECT_LABEL = "openssl"
PROJECT_DESC = ""
# PROJECT_DESC = "OpenSSL is a widely-used software library ..."

RES_ROOT_PATH = "RES"

# 已成功得到结论（set_conclusion）的警报位置 "fl:ln"（各缺陷类 source_loc），跨运行追加；命中则跳过分析
ANALYZED_LOCATIONS_FILE = os.path.join(RES_ROOT_PATH, "analyzed_allocation_locations.txt")

LLM_TYPE = "DeepSeek"

import os

# 三路径配置：源码根、bitcode 文件、SAR 文件（均为显式路径，不再拼接）
# 项目源码根目录（os.walk / 相对路径基准）
PROJECT_ROOT = "/data/OpenHarmony-4.0-Release"
# PROJECT_ROOT = "/data/PUT/openssl-67dc995e"

# bitcode 完整路径（graph-reader 与 path-cond 等统一使用）
BITCODE_PATH = "/data/linked/base_security_00.bc"
# BITCODE_PATH = "/data/OpenHarmony-4.1-Release.bc"

# SAR 完整路径（无批处理目录或目录无效时作为唯一输入）
SAR_PATH = "SAR/oh-4.0-release-leak/base_security/base_security_00.txt"
# SAR_PATH = "SAR/openssl-67dc995e.txt"

# 批处理：SAR_BATCH_DIRS 非空时优先，按列表顺序依次扫各目录下全部 .txt；否则用 SAR_BATCH_DIR 单目录
SAR_BATCH_DIRS = [
    "SAR/oh-4.0-release-leak/foundation_communication",
    "SAR/oh-4.0-release-leak/foundation_systemabilitymgr",
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

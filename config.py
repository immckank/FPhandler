# 三路径配置：源码根、bitcode 文件、SAR 文件（均为显式路径，不再拼接）
# 项目源码根目录（os.walk / 相对路径基准）
PROJECT_ROOT = "/data/OpenHarmony-4.1-Release"
# PROJECT_ROOT = "/data/PUT/openssl-67dc995e"

# bitcode 完整路径（graph-reader 与 path-cond 等统一使用）
BITCODE_PATH = "/data/bundle_00.bc"
# BITCODE_PATH = "/data/OpenHarmony-4.1-Release.bc"

# SAR 完整路径（静态分析结果文本）
SAR_PATH = "SAR/bundle00_leak.txt"
# SAR_PATH = "SAR/openssl-67dc995e.txt"

# LLM 提示用展示名
PROJECT_LABEL = "OpenHarmony-4.1-Release"
# PROJECT_LABEL = "openssl"
PROJECT_DESC = ""
# PROJECT_DESC = "OpenSSL is a widely-used software library ..."

RES_ROOT_PATH = "RES"
LLM_TYPE = "DeepSeek"

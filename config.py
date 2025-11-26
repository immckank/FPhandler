# program under test 
PUT_ROOT_PATH = "PUT/libtiff_root/libtiff-57449991" 
# PUT_ROOT_PATH = "PUT/openssl_root/openssl-2dbfa844" 
# PUT_NAME = "openssl"
PUT_NAME = "libtiff"

PROJECT_NAME = "libtiff"
# PROJECT_NAME = "openssl"
# PROJECT_DESC = "Memcached is a long-running background service (daemon) that continuously runs in the background after the server starts. It listens on a specified network port and manages a pre-allocated block of memory."
PROJECT_DESC = "Libtiff is a widely-used software library that provides a set of programming interfaces for applications. It does not run as a standalone program but is linked by other software to handle the reading and writing of TIFF (Tagged Image File Format) image files."
# PROJECT_DESC = "OpenSSL is a widely-used software library that does not run as a standalone program but is linked by other software to handle cryptographic functions and secure network protocols (like TLS/SSL)."
# static analysis result
SAR_ROOT_PATH = "SAR"
# sar_name = "openssl-2dbfa844-test20.txt"
# sar_name = "libtiff-b9b93f66.txt"
sar_name = "libtiff-57449991.txt"
# sar_name = "openssl-67dc995e.txt"
alter_index = 0

# result
RES_ROOT_PATH = "RES"

# LLM_TYPE = "DeepSeek"
LLM_TYPE = "DRES/RESULTeepSeek"

# free / function / path
ANALYZER_TYPE = "function"

# For layered workflow
LAYERED_WORKFLOW_PIPELINE = ["function", "path"]

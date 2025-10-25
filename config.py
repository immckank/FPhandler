import logging
import os

# program under test 
PUT_ROOT_PATH = "PUT/libtiff-b9b93f66" 
# PUT_ROOT_PATH = "PUT/openssl-67dc995e"
PUT_NAME = "libtiff"
# PUT_NAME = "openssl"

PROJECT_NAME = "libtiff"
# PROJECT_NAME = "openssl"
# PROJECT_DESC = "Memcached is a long-running background service (daemon) that continuously runs in the background after the server starts. It listens on a specified network port and manages a pre-allocated block of memory."
PROJECT_DESC = "Libtiff is a widely-used software library that provides a set of programming interfaces for applications. It does not run as a standalone program but is linked by other software to handle the reading and writing of TIFF (Tagged Image File Format) image files."
# PROJECT_DESC += "Error handling mechanism: When a function returns 'return(0);' because of an error, the error status is propagated up to its caller, and is ultimately caught by the appropriate handler."
# static analysis result
SAR_ROOT_PATH = "SAR"
sar_name = "libtiff-b9b93f66.txt"
alter_index = 0

# result
RES_ROOT_PATH = "RES"

LLM_TYPE = "DeepSeek"

# free / function
ANALYZER_TYPE = "function"

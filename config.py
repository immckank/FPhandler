import logging
import os

# program under test 
PUT_ROOT_PATH = "PUT" 
PUT_NAME = "memcached"

PROJECT_NAME = "memcached"
PROJECT_DESC = "Memcached is a long-running background service (daemon) that continuously runs in the background after the server starts. It listens on a specified network port and manages a pre-allocated block of memory."

# static analysis result
SAR_ROOT_PATH = "SAR"
sar_name = "memcached_PARTIALLEAKTEST.txt"
alter_index = 0

# result
RES_ROOT_PATH = "RES"

LLM_TYPE = "DeepSeek"

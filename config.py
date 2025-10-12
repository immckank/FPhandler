import logging
import os
import datetime

PUT_ROOT_PATH = "PUT"
PUT_NAME = "memcached"

PROJECT_NAME = "memcached"

SARIF_ROOT_PATH = "SARIF"
sarif_name = "memcached_NEVERFREETEST.txt"
alter_index = 0

RES_ROOT_PATH = "RES"

LLM_TYPE = "DeepSeek"

# logging config
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s [%(levelname)s] - %(message)s',
#     handlers=[
#         logging.FileHandler(os.path.join(RES_ROOT_PATH, f'{time_str}_{LLM_TYPE}_{PROJECT_NAME}_{PUT_NAME}_log.txt')),
#         logging.StreamHandler()
#     ]
# )

#
import logging
import os
import datetime

PUT_ROOT_PATH = "PUT"
RES_ROOT_PATH = "RES"
SARIF_ROOT_PATH = "SARIF"


PROJECT_NAME = "memcached"
SARIF_NAME = "memcached_PARTIALLEAKTEST.txt"
PUT_NAME = "memcached"


LLM_TYPE = "DeepSeek"


# 获取时间YYYY-MM-DD-HH:MM:SS
time_str = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')

# logging config
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(RES_ROOT_PATH, f'{time_str}_{LLM_TYPE}_{PROJECT_NAME}_{PUT_NAME}_log.txt')),
        logging.StreamHandler()
    ]
)

#
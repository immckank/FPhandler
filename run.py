import logging
import os
from datetime import datetime

from config import *
from utils import *

from alter_handler import AlterAnalyzer
from llm import create_analyzer


    
if __name__ == "__main__":
    # main_logger = setup_logger(log_type="main")
    # main_logger.info(f"start")
    # if not sar_name:
    #     main_logger.info(f"analyzing sar dir {SAR_ROOT_PATH}")
    #     for root, dirs, files in os.walk(SAR_ROOT_PATH):
    #         for file in files:
    #             # TODO
    #             if file.endswith(".sar"):
    #                 sar_name = file
    #                 main_logger.info(f"analyzing {sar_name}")
    #                 analyzer = AlterAnalyzer()
    #                 analyzer.read_alter_file(SAR_ROOT_PATH, sar_name)
    #                 analyzer.handle_memory_leak()
    # else:
    #     main_logger.info(f"analyzing {sar_name}")
    #     analyzer = AlterAnalyzer()
    #     analyzer.read_alter_file(SAR_ROOT_PATH, sar_name)
    #     analyzer.handle_memory_leak()
    main_logger = setup_logger(log_type="main")
    main_logger.info(f"start")
    main_logger.info(f"analyzing {sar_name}")
    reader = AlterAnalyzer()
    alter_list = reader.read_alter_file(SAR_ROOT_PATH, sar_name)
    alter_num = len(alter_list)
    main_logger.info(f"total alter number: {alter_num}")
    analyzer = create_analyzer(ANALYZER_TYPE)
    for i in range(alter_num):
        main_logger.info(f"analysing alter index : {i+1} / {alter_num}")
        analyzer.responseForAlter(alter_list[i])
        
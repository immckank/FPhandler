import logging
import os
from datetime import datetime

from config import *
from utils import *

from alter_handler import AlterAnalyzer
    
if __name__ == "__main__":
    main_logger = setup_logger(log_type="main")
    main_logger.info(f"start")
    if not sarif_name:
        main_logger.info(f"analyzing sarif dir {SARIF_ROOT_PATH}")
        for root, dirs, files in os.walk(SARIF_ROOT_PATH):
            for file in files:
                if file.endswith(".sarif"):
                    sarif_name = file
                    main_logger.info(f"analyzing {sarif_name}")
                    analyzer = AlterAnalyzer()
                    analyzer.read_alter_file(SARIF_ROOT_PATH, sarif_name)
                    analyzer.handle_memory_leak()
    else:
        main_logger.info(f"analyzing {sarif_name}")
        analyzer = AlterAnalyzer()
        analyzer.read_alter_file(SARIF_ROOT_PATH, sarif_name)
        analyzer.handle_memory_leak()
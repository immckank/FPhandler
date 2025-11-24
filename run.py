import logging
import os
import datetime
import threading
import json

from config import *
from utils import *

from alter_handler import AlterAnalyzer
from analyzers import create_analyzer
from command_caller import CommandCaller
from analyzers.path_builder_agent import FunctionPathBuilderAgent, FunctionNodeBuilderAgent, FunctionPathCheckerAgent
import analysis_operators
from openai import OpenAI

# 定义一个元组 source_location, eq_position
source_location_eq_position_list = [
    ("tif_dirread.c:1166", 6),
    ("tif_dirread.c:1519", 6),
    ("tif_dirread.c:1686", 6),
    ("tif_dirread.c:1855", 6),
    ("tif_dirread.c:2188", 6),
    ("tif_dirread.c:2323", 6),
    ("tif_dirread.c:2568", 6),
    ("tif_dirread.c:2797", 6),
    ("tif_dirread.c:4981", 9),
    ("tif_dirwrite.c:839", 8),
    ("tif_dirwrite.c:1688", 7),
    ("tif_dirwrite.c:1746", 7),
    ("tif_dirwrite.c:1934", 4),
    ("tif_getimage.c:370", 18),
    ("tif_jpeg.c:2057", 20),
    ("tif_read.c:1421", 20),
    ("tif_write.c:658", 6),
]

def test_old_function_path_builder_agent():
    # """测试FunctionPathBuilderAgent类"""
    # 初始化CommandCaller（某些analysis_operators功能需要）    
    start_loc = "tif_dirread.c:2323"
    
    func = analysis_operators.find_function_body("TIFFReadDirEntryFloatArray")
    if not func or (isinstance(func, dict) and func.get("error")):
        func = analysis_operators.find_current_function(start_loc)
    
    print(func)
    
    var_info = {
        "var_name": "data",
        "var_type": "local_var",
        "arg_index": 6,
        "gep_info": {
            "gep_type": "not_struct",
            "baseobj_name": None,
            "member_name": None,
            "offset": 0,
            "baseobj_type": "ptr",
        },
    }
    
    # 创建OpenAI客户端（使用DeepSeek）
    model_name = "deepseek-chat"
    client = OpenAI(
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    
    # 创建FunctionPathBuilderAgent实例
    agent = FunctionPathBuilderAgent(
        current_function_info=func,
        var_info=var_info,
        start_location=start_loc,
        client=client,
        model_name=model_name,
    )
    
    # 构建路径
    result_paths = agent.build_paths()
    
    # 输出结果
    print(json.dumps(result_paths, ensure_ascii=False, indent=2))
    
    # 清理：请求graph-reader退出
    try:
        caller = CommandCaller()
        caller.send_query({"command": "exit"})
    except Exception:
        pass


def test_new_function_path_builder_agent():
    """测试新版 FunctionPathBuilderAgent（analyze_paths 流程）"""
    
    run_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RES", "RUN")
    os.makedirs(run_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(run_dir, f"path-builder-{timestamp}.log")

    logger = logging.getLogger(f"path_builder_{timestamp}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    try:
        for source_location, eq_position in source_location_eq_position_list:
            # if not (source_location == "tif_getimage.c:370" and eq_position == 18):
            #     continue

            logger.info(
                "Start analyze source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )

            # 创建OpenAI客户端（使用DeepSeek）
            model_name = "deepseek-chat"
            client = OpenAI(
                api_key=os.environ.get("DEEPSEEK_API_KEY"),
                base_url="https://api.deepseek.com",
            )

            agent = FunctionPathBuilderAgent(
                source_location=source_location,
                eq_position=eq_position,
                client=client,
                model_name=model_name,
            )

            # 运行新版路径分析流程
            result_paths = agent.analyze_paths()

            # 输出结果
            result_json = json.dumps(result_paths, ensure_ascii=False, indent=2)
            print(result_json)
            logger.info("Analyze result: %s", result_json)
    finally:
        # 在所有迭代完成后关闭handler
        handler.close()
        logger.removeHandler(handler)

        # 清理：请求graph-reader退出
        try:
            caller = CommandCaller()
            caller.send_query({"command": "exit"})
        except Exception:
            pass


def test_function_node_builder_agent():
    """测试FunctionNodeBuilderAgent类"""
    # 初始化CommandCaller（某些analysis_operators功能需要）
    start_loc = "tif_dirread.c:2323"
    
    func = analysis_operators.find_function_body("TIFFReadDirEntryFloatArray")
    if not func or (isinstance(func, dict) and func.get("error")):
        func = analysis_operators.find_current_function(start_loc)
    
    print(func)
    
    var_info = {
        "var_name": "data",
        "var_type": "local_var",
        "arg_index": 6,
        "gep_info": {
            "gep_type": "not_struct",
            "baseobj_name": None,
            "member_name": None,
            "offset": 0,
            "baseobj_type": "ptr",
        },
    }
    
    # 创建OpenAI客户端（使用DeepSeek）
    model_name = "deepseek-chat"
    client = OpenAI(
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    
    # 创建FunctionNodeBuilderAgent实例
    agent = FunctionNodeBuilderAgent(
        var_info=var_info,
        start_line=start_loc,
        function_info=func,
        client=client,
        model_name=model_name,
    )
    
    # 识别值流节点
    result_nodes = agent.identify_value_flow_nodes()
    
    # 输出结果
    print(json.dumps(result_nodes, ensure_ascii=False, indent=2))
    
    # 清理：请求graph-reader退出
    try:
        caller = CommandCaller()
        caller.send_query({"command": "exit"})
    except Exception:
        pass


def test_function_path_checker_agent():
    """测试FunctionPathCheckerAgent类 - 直接验证路径可行性"""
    
    run_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RES", "RUN")
    os.makedirs(run_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(run_dir, f"path-checker-{timestamp}.log")

    logger = logging.getLogger(f"path_checker_{timestamp}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    try:
        # 创建OpenAI客户端（使用DeepSeek）
        model_name = "deepseek-chat"
        client = OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        
        total_tested = 0
        total_feasible = 0
        total_not_feasible = 0
        
        # 循环测试所有位置对
        for idx, (source_location, eq_position) in enumerate(source_location_eq_position_list, start=1):
            logger.info(
                "Start analyze source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )
            
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(source_location_eq_position_list)}] Testing: {source_location} eq_position={eq_position}")
            print(f"{'='*80}")
            
            try:
                # 使用FunctionPathBuilderAgent的init_function_raw_path获取基础路径数据
                print("\n=== Getting raw path data ===")
                path_builder_agent = FunctionPathBuilderAgent(
                    source_location=source_location,
                    eq_position=eq_position,
                    client=client,
                    model_name=model_name,
                )
                
                # 获取原始路径数据（已在__init__中通过init_function_raw_path获取）
                path_data = path_builder_agent.path_data
                print(f"Got {len(path_data)} paths")
                
                # 使用FunctionPathCheckerAgent检查路径可达性
                print("\n=== Checking path feasibility ===")
                path_checker_agent = FunctionPathCheckerAgent(
                    path_data=path_data,
                    client=client,
                    model_name=model_name,
                )
                
                # 运行路径可达性检查
                checked_paths = path_checker_agent.analyze_paths()
                
                # 输出路径检查结果
                result_json = json.dumps(checked_paths, ensure_ascii=False, indent=2)
                print("\n=== Results ===")
                print(result_json)
                logger.info("Analyze result: %s", result_json)
                
                # 统计结果
                feasible_count = sum(1 for p in checked_paths if p.get("feasibility") == "feasible")
                not_feasible_count = sum(1 for p in checked_paths if p.get("feasibility") == "not feasible")
                
                print(f"\n=== Summary for {source_location} ===")
                print(f"Total paths: {len(checked_paths)}")
                print(f"Feasible paths: {feasible_count}")
                print(f"Not feasible paths: {not_feasible_count}")
                
                total_tested += len(checked_paths)
                total_feasible += feasible_count
                total_not_feasible += not_feasible_count
                
            except Exception as e:
                error_msg = f"Error processing {source_location}: {str(e)}"
                print(f"\n!!! {error_msg}")
                logger.error(error_msg, exc_info=True)
                import traceback
                traceback.print_exc()
                continue
        
        # 输出总体统计
        print(f"\n{'='*80}")
        print(f"=== OVERALL SUMMARY ===")
        print(f"{'='*80}")
        print(f"Total locations tested: {len(source_location_eq_position_list)}")
        print(f"Total paths analyzed: {total_tested}")
        print(f"Total feasible paths: {total_feasible}")
        print(f"Total not feasible paths: {total_not_feasible}")
        
        logger.info(
            "Overall summary: total_locations=%d total_paths=%d feasible=%d not_feasible=%d",
            len(source_location_eq_position_list),
            total_tested,
            total_feasible,
            total_not_feasible
        )
        
    finally:
        # 在所有迭代完成后关闭handler
        handler.close()
        logger.removeHandler(handler)

        # 清理：请求graph-reader退出
        try:
            caller = CommandCaller()
            caller.send_query({"command": "exit"})
        except Exception:
            pass


if __name__ == "__main__":
    # 测试FunctionPathBuilderAgent
    # test_function_path_builder_agent()
    # exit(0)
    
    # 测试新版FunctionPathBuilderAgent（analyze_paths 流程）
    # test_new_function_path_builder_agent()
    
    # 测试FunctionPathCheckerAgent
    test_function_path_checker_agent()
    
    # main_logger = setup_logger(log_type="main")
    # main_logger.info(f"start")
    # main_logger.info(f"analyzing {sar_name}")
    # # Start CommandCaller initialization in the background; do not block main flow
    # threading.Thread(target=CommandCaller, kwargs={}, daemon=True).start()
    # reader = AlterAnalyzer()
    # alter_list = reader.read_alter_file(SAR_ROOT_PATH, sar_name)
    # alter_num = len(alter_list)
    # main_logger.info(f"total alter number: {alter_num}")
    # analyzer = create_analyzer()
    # for i in range(alter_num):
    #     main_logger.info(f"analysing alter index : {i+1} / {alter_num}")
    #     analyzer.responseForAlter(alter_list[i])
    # # After analysis completes, explicitly ask graph-reader to exit
    # try:
    #     caller = CommandCaller()
    #     caller.send_query({"command": "exit"})
    # except Exception:
    #     pass
        
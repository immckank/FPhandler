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
from analyzers.path_z3_checker import PathZ3CheckerAgent
from analyzers.path_branch_extractor import PathBranchExtractorAgent
from analyzers.cross_function_analyzer import CrossFunctionMemoryFlowAnalyzer
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

checker_test_data = [
    # 839 8
    ("tif_dirwrite.c:839", 8),
]


def ensure_ctags_ready(force=False):
    """
    Ensure the project-wide ctags index exists before running analyzers.
    """
    result = generate_ctags_index(force=force)
    if isinstance(result, dict):
        if result.get("error"):
            logging.warning("ctags index unavailable: %s", result["error"])
        elif result.get("status") == "generated":
            logging.info("ctags index generated at %s", result.get("path"))
    return result

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


def test_new_function_path_builder_agent(test_data):
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
        for source_location, eq_position in test_data:
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


def test_function_path_checker_agent(test_data):
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
        for idx, (source_location, eq_position) in enumerate(test_data, start=1):
            logger.info(
                "Start analyze source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )
            
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(test_data)}] Testing: {source_location} eq_position={eq_position}")
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
        print(f"Total locations tested: {len(test_data)}")
        print(f"Total paths analyzed: {total_tested}")
        print(f"Total feasible paths: {total_feasible}")
        print(f"Total not feasible paths: {total_not_feasible}")
        
        logger.info(
            "Overall summary: total_locations=%d total_paths=%d feasible=%d not_feasible=%d",
            len(test_data),
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


z3_checker_test_data = [
    # (source_location, eq_position)
    ("tif_dirwrite.c:839", 8),
]

def test_path_z3_checker_agent(test_data):
    """测试PathZ3CheckerAgent类 - 针对每条路径生成Z3验证脚本"""
    
    run_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RES", "RUN")
    os.makedirs(run_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(run_dir, f"z3-checker-{timestamp}.log")

    logger = logging.getLogger(f"z3_checker_{timestamp}")
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
        
        for idx, (source_location, eq_position) in enumerate(test_data, start=1):
            logger.info(
                "Start generate Z3 scripts for source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )
            
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(test_data)}] Testing Z3 Script Generation: {source_location} eq_position={eq_position}")
            print(f"{'='*80}")
            
            try:
                # 1. 获取基础路径数据
                print("\n=== Getting raw path data ===")
                path_builder_agent = FunctionPathBuilderAgent(
                    source_location=source_location,
                    eq_position=eq_position,
                    client=client,
                    model_name=model_name,
                )
                
                path_data = path_builder_agent.path_data
                print(f"Got {len(path_data)} paths")
                
                if not path_data:
                    msg = "No paths found, skip"
                    print(msg)
                    logger.warning(msg)
                    continue
                
                # 2. 初始化PathZ3CheckerAgent
                print("\n=== Initializing PathZ3CheckerAgent ===")
                z3_checker = PathZ3CheckerAgent(
                    path_data=path_data,
                    client=client,
                    model_name=model_name,
                )
                
                # 3. 针对每条路径生成脚本
                for path in path_data:
                    target_path_id = path.get("path_id")
                    if target_path_id is None:
                        continue
                    
                    print(f"\n=== Generating Z3 script for path {target_path_id} ===")
                    try:
                        result = z3_checker.generate_z3_script(target_path_id)
                        print("\n=== Generation Result ===")
                        print(result)
                        logger.info("Generation result for path %s: %s", target_path_id, result)
                    except Exception as path_err:
                        err_msg = f"Failed to generate Z3 script for path {target_path_id}: {path_err}"
                        print(err_msg)
                        logger.error(err_msg, exc_info=True)
                    
            except Exception as e:
                error_msg = f"Error processing {source_location} path {target_path_id}: {str(e)}"
                print(f"\n!!! {error_msg}")
                logger.error(error_msg, exc_info=True)
                import traceback
                traceback.print_exc()
                continue
            
    finally:
        handler.close()
        logger.removeHandler(handler)
        
        try:
            caller = CommandCaller()
            caller.send_query({"command": "exit"})
        except Exception:
            pass


def test_path_branch_extractor_agent(test_data):
    """测试PathBranchExtractorAgent类 - 针对每条路径提取约束"""
    
    run_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RES", "RUN")
    os.makedirs(run_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(run_dir, f"branch-extractor-{timestamp}.log")

    logger = logging.getLogger(f"branch_extractor_{timestamp}")
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
        
        for idx, (source_location, eq_position) in enumerate(test_data, start=1):
            logger.info(
                "Start extract constraints for source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )
            
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(test_data)}] Testing Branch Extractor: {source_location} eq_position={eq_position}")
            print(f"{'='*80}")
            
            try:
                # 1. 获取基础路径数据
                print("\n=== Getting raw path data ===")
                path_builder_agent = FunctionPathBuilderAgent(
                    source_location=source_location,
                    eq_position=eq_position,
                    client=client,
                    model_name=model_name,
                )
                
                path_data = path_builder_agent.path_data
                print(f"Got {len(path_data)} paths")
                
                if not path_data:
                    msg = "No paths found, skip"
                    print(msg)
                    logger.warning(msg)
                    continue
                
                # 2. 初始化PathBranchExtractorAgent
                print("\n=== Initializing PathBranchExtractorAgent ===")
                extractor = PathBranchExtractorAgent(
                    path_data=path_data,
                    client=client,
                    model_name=model_name,
                )
                
                # 3. 针对每条路径提取约束
                for path in path_data:
                    target_path_id = path.get("path_id")
                    if target_path_id is None:
                        continue
                    
                    print(f"\n=== Extracting constraints for path {target_path_id} ===")
                    try:
                        result = extractor.extract_path_constraints(target_path_id)
                        print("\n=== Extraction Result ===")
                        constraints = result.get('execution_trace', [])
                        print(json.dumps(constraints, indent=2, ensure_ascii=False))
                        logger.info(
                            "Extraction result for path %s: %s",
                            target_path_id,
                            json.dumps(constraints, ensure_ascii=False),
                        )
                    except Exception as path_err:
                        err_msg = f"Failed to extract constraints for path {target_path_id}: {path_err}"
                        print(err_msg)
                        logger.error(err_msg, exc_info=True)
                    
            except Exception as e:
                error_msg = f"Error processing {source_location} path {target_path_id}: {str(e)}"
                print(f"\n!!! {error_msg}")
                logger.error(error_msg, exc_info=True)
                import traceback
                traceback.print_exc()
                continue
            
    finally:
        handler.close()
        logger.removeHandler(handler)
        
        try:
            caller = CommandCaller()
            caller.send_query({"command": "exit"})
        except Exception:
            pass


def test_cross_function_memory_flow_analyzer(test_data):
    """测试CrossFunctionMemoryFlowAnalyzer类 - 跨函数内存流分析"""
    
    run_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RES", "RUN")
    os.makedirs(run_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(run_dir, f"cross-function-analyzer-{timestamp}.log")

    logger = logging.getLogger(f"cross_function_analyzer_{timestamp}")
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
        
        total_analyzed = 0
        total_nodes = 0
        total_paths = 0
        
        # 循环测试所有位置对
        for idx, (source_location, eq_position) in enumerate(test_data, start=1):
            logger.info(
                "Start cross-function analysis for source_location=%s eq_position=%s",
                source_location,
                eq_position,
            )
            
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(test_data)}] Testing CrossFunctionMemoryFlowAnalyzer: {source_location} eq_position={eq_position}")
            print(f"{'='*80}")
            
            try:
                # 1. 创建分析器
                print("\n=== Creating CrossFunctionMemoryFlowAnalyzer ===")
                analyzer = CrossFunctionMemoryFlowAnalyzer.from_location(
                    location=source_location,
                    eq_position=eq_position,
                    client=client,
                    model_name=model_name,
                )
                
                print(f"Root node: {analyzer.root_node.function_name} at {analyzer.root_node.start_location}")
                
                # 2. 运行分析
                print("\n=== Running cross-function analysis ===")
                all_nodes = analyzer.analyze()
                
                print(f"\n=== Analysis Complete ===")
                print(f"Total nodes analyzed: {len(all_nodes)}")
                
                # 3. 输出分析树结构
                print("\n=== Analysis Tree Structure ===")
                def print_tree(node, indent=0):
                    """递归打印分析树"""
                    prefix = "  " * indent
                    status_icon = {
                        "pending": "⏳",
                        "analyzing": "🔄",
                        "completed": "✅",
                        "terminated": "❌"
                    }.get(node.analysis_status, "?")
                    
                    print(f"{prefix}{status_icon} Node {node.node_id}: {node.function_name} ({node.analysis_status})")
                    print(f"{prefix}   Location: {node.start_location}")
                    print(f"{prefix}   Paths: {len(node.paths)}, Results: {len(node.path_analysis_results)}")
                    
                    if node.path_analysis_results:
                        classifications = [r.get("classification") for r in node.path_analysis_results]
                        print(f"{prefix}   Classifications: {', '.join(set(classifications))}")
                    
                    for child in node.children:
                        print_tree(child, indent + 1)
                
                print_tree(analyzer.root_node)
                
                # 4. 输出详细结果
                print("\n=== Detailed Results ===")
                for node in all_nodes:
                    print(f"\n--- Node {node.node_id}: {node.function_name} ---")
                    print(f"Status: {node.analysis_status}")
                    print(f"Location: {node.start_location}")
                    print(f"Paths: {len(node.paths)}")
                    print(f"Path Analysis Results: {len(node.path_analysis_results)}")
                    
                    if node.path_analysis_results:
                        print("Path Classifications:")
                        for result in node.path_analysis_results:
                            path_id = result.get("path_id")
                            classification = result.get("classification")
                            reason = result.get("reason", "")
                            key_operation = result.get("key_operation")
                            
                            print(f"  Path {path_id}: {classification}")
                            if reason:
                                print(f"    Reason: {reason[:100]}...")  # Truncate long reasons
                            if key_operation:
                                callee = key_operation.get("callee_function_name")
                                if callee:
                                    print(f"    Callee: {callee}")
                    
                    if node.children:
                        print(f"Children: {len(node.children)}")
                        for child in node.children:
                            print(f"  -> {child.function_name} at {child.start_location}")
                
                # 5. 统计信息
                node_count = len(all_nodes)
                path_count = sum(len(node.path_analysis_results) for node in all_nodes)
                
                print(f"\n=== Summary for {source_location} ===")
                print(f"Total nodes in analysis tree: {node_count}")
                print(f"Total paths analyzed: {path_count}")
                
                total_analyzed += 1
                total_nodes += node_count
                total_paths += path_count
                
                # 6. 输出JSON格式的结果（可选）
                result_summary = {
                    "source_location": source_location,
                    "eq_position": eq_position,
                    "root_function": analyzer.root_node.function_name,
                    "total_nodes": node_count,
                    "total_paths": path_count,
                    "nodes": [
                        {
                            "node_id": node.node_id,
                            "function_name": node.function_name,
                            "status": node.analysis_status,
                            "path_count": len(node.path_analysis_results),
                            "classifications": [r.get("classification") for r in node.path_analysis_results],
                            "children_count": len(node.children)
                        }
                        for node in all_nodes
                    ]
                }
                
                result_json = json.dumps(result_summary, ensure_ascii=False, indent=2)
                logger.info("Analysis result: %s", result_json)
                
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
        print(f"Total locations analyzed: {total_analyzed}")
        print(f"Total nodes created: {total_nodes}")
        print(f"Total paths analyzed: {total_paths}")
        if total_analyzed > 0:
            print(f"Average nodes per location: {total_nodes / total_analyzed:.2f}")
            print(f"Average paths per location: {total_paths / total_analyzed:.2f}")
        
        logger.info(
            "Overall summary: total_locations=%d total_nodes=%d total_paths=%d",
            total_analyzed,
            total_nodes,
            total_paths
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
    ensure_ctags_ready()
    # 测试FunctionPathBuilderAgent
    # test_function_path_builder_agent(source_location_eq_position_list)
    # exit(0)
    
    # 测试新版FunctionPathBuilderAgent（analyze_paths 流程）
    # test_new_function_path_builder_agent(source_location_eq_position_list)
    
    # 测试CrossFunctionMemoryFlowAnalyzer
    test_cross_function_memory_flow_analyzer([source_location_eq_position_list[0]])
    
    # 测试FunctionPathCheckerAgent
    # test_function_path_checker_agent(checker_test_data)

    # 测试PathZ3CheckerAgent
    # test_path_z3_checker_agent(z3_checker_test_data)
    
    # 测试PathBranchExtractorAgent
    # test_path_branch_extractor_agent(z3_checker_test_data)
    
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

import logging
import os
import sys
from datetime import datetime
import threading
import json

# 将项目根目录添加到 sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import *
from utils import *

from alter_handler import AlterAnalyzer
from llm_layered import create_analyzer
from command_caller import CommandCaller

def interpret_path_analysis_result(path_analysis_list):
    """
    解释详细的路径分析列表，以产生最终的 TP/FP 结论。
    """
    if not path_analysis_list or not isinstance(path_analysis_list, list):
        return {"classification": "UNCERTAIN", "reason": "Path analysis did not return a valid result."}

    for path in path_analysis_list:
        if not path or not isinstance(path, list):
            continue

        # 查找路径中最后一个有意义的段
        # 路径可能以 `{"classification": "done"}` 标记结束
        last_segment = None
        if len(path) > 0:
            if path[-1].get("classification") == "done" and len(path) > 1:
                last_segment = path[-2]
            elif path[-1].get("classification") != "done":
                last_segment = path[-1]

        if last_segment and last_segment.get("classification") == "Leak":
            return {
                "classification": "TP",
                "reason": "A memory leak path was found by the path analyzer."
            }

    # 如果在检查所有路径后未找到“Leak”路径，则认为它是误报。
    return {
        "classification": "FP",
        "reason": "All analyzed memory paths are safely handled (e.g., freed, returned, or transferred)."
    }
    
if __name__ == "__main__":
    main_logger = setup_logger(log_type="main", analyzer_type_override="layered")
    result_logger = setup_logger(log_type="result", analyzer_type_override="layered") # 用于最终 TP/FP 结果的记录器
    analysis_logger = setup_logger(log_type="analysis", analyzer_type_override="layered")
    
    main_logger.info(f"start layered analysis with pipeline: {LAYERED_WORKFLOW_PIPELINE}")
    main_logger.info(f"analyzing {sar_name}")
    # 在后台启动 CommandCaller 初始化；不阻塞主流程
    threading.Thread(target=CommandCaller, kwargs={}, daemon=True).start()
    reader = AlterAnalyzer()
    alter_list = reader.read_alter_file(SAR_ROOT_PATH, sar_name)
    alter_num = len(alter_list)
    main_logger.info(f"total alter number: {alter_num}")

    # 创建管道中定义的所有分析器
    main_logger.info("Initializing analyzers...")
    analyzers = {tier_name: create_analyzer(tier_name, result_logger, analysis_logger) for tier_name in set(LAYERED_WORKFLOW_PIPELINE)}
    main_logger.info(f"Analyzers initialized: {list(analyzers.keys())}")

    for i in range(alter_num):
        main_logger.info(f"======== Analysing alter index : {i+1} / {alter_num} ========")
        alert = alter_list[i]
        
        last_result = None
        last_tier_name = ""
        tier_results = []

        # 执行管道
        for tier_idx, tier_name in enumerate(LAYERED_WORKFLOW_PIPELINE):
            main_logger.info(f"--- Starting Tier {tier_idx + 1}: {tier_name} Workflow ---")
            
            analyzer = analyzers[tier_name]
            current_result = analyzer.responseForAlter(alert)
            last_result = current_result
            last_tier_name = tier_name
            
            tier_conclusion = {}
            if tier_name == "path":
                tier_conclusion = interpret_path_analysis_result(current_result)
            else:
                tier_conclusion = current_result

            classification = tier_conclusion.get("classification", "UNCERTAIN")
            main_logger.info(f"Tier {tier_idx + 1} ({tier_name}) Conclusion: {classification}")
            
            tier_results.append({
                "tier_name": tier_name,
                "classification": classification,
                "reason": tier_conclusion.get("reason", "N/A")
            })

            # 如果该层给出了确定的 FP，则停止此警报的管道
            if classification == "FP":
                break
        
        # --- 完成并记录结果 ---
        final_conclusion = None
        # 如果最后执行的层是 'path'，则解释其详细结果
        if last_tier_name == "path":
            final_conclusion = interpret_path_analysis_result(last_result)
        else: # 否则，最后一层的结果就是最终结果
            final_conclusion = last_result

        main_logger.info(f"--- Pipeline finished. Final Conclusion: {final_conclusion.get('classification')} ---")

        # 准备一个包含基本警报信息的字典用于记录
        log_string = (
            f"Alert Source: {alert.get_source_location()}\n"
            f"Bug Type: {alert.get_leak_type() if hasattr(alert, 'get_leak_type') else alert.get_defect_type()}\n"
        )
        log_string += "Tier-based Analysis:\n"
        for res in tier_results:
            log_string += f"  - Tier: {res['tier_name']}, Conclusion: {res['classification']}, Reason: {res['reason']}\n"
        
        log_string += (
            f"Final Conclusion: {final_conclusion.get('classification')}\n"
            f"Final Reason: {final_conclusion.get('reason')}\n"
            f"--------------------------------------------------\n"
        )
        
        result_logger.info(log_string)

    # 分析完成后，明确要求 graph-reader 退出
    try:
        caller = CommandCaller()
        caller.send_query({"command": "exit"})
    except Exception:
        pass
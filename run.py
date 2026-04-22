import logging
import os
from datetime import datetime
import threading

from config import *
import config as _cfg
from utils import *

from alter_handler import AlterAnalyzer
from free_analyzer import create_analyzer
from command_caller import CommandCaller


def _txt_files_in_dir(d):
    names = sorted(
        f
        for f in os.listdir(d)
        if f.lower().endswith(".txt") and os.path.isfile(os.path.join(d, f))
    )
    return [os.path.join(d, f) for f in names]


def _effective_batch_dir_list():
    """SAR_BATCH_DIRS（列表）优先于 SAR_BATCH_DIR（单目录）。"""
    dirs_cfg = getattr(_cfg, "SAR_BATCH_DIRS", None)
    if dirs_cfg:
        return [str(x).strip() for x in dirs_cfg if str(x).strip()]
    d = getattr(_cfg, "SAR_BATCH_DIR", None)
    d = (d or "").strip()
    return [d] if d else []


def _resolve_sar_paths():
    paths = []
    for d in _effective_batch_dir_list():
        if d and os.path.isdir(d):
            paths.extend(_txt_files_in_dir(d))
    if paths:
        return paths, True
    return [SAR_PATH], False


def _run_log_stem_for_batch_dirs(dirs):
    if not dirs:
        return None
    if len(dirs) == 1:
        return os.path.basename(os.path.normpath(dirs[0])) or "sar-batch"
    parts = [os.path.basename(os.path.normpath(x)) for x in dirs]
    return "-".join(parts)


def _load_analyzed_location_keys(path):
    if not path or not os.path.isfile(path):
        return set()
    keys = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s:
                keys.add(s)
    return keys


def _append_analyzed_location(path, key):
    if not key:
        return
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(key + "\n")


def _alter_location_key(alter):
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc") and alter.get_source_loc()
        else None
    )
    return location_string_from_source_loc(loc)


if __name__ == "__main__":
    batch_dirs = [
        d
        for d in _effective_batch_dir_list()
        if d and os.path.isdir(d)
    ]
    sar_paths, sar_paths_from_batch = _resolve_sar_paths()
    if sar_paths_from_batch and batch_dirs:
        _cfg.RUN_SESSION_TIME_STR = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        _cfg.RUN_LOG_STEM = _run_log_stem_for_batch_dirs(batch_dirs)

    main_logger = setup_logger(log_type="main")
    main_logger.info("start")
    main_logger.info("SAR files: %s", sar_paths)

    analyzed_path = getattr(_cfg, "ANALYZED_LOCATIONS_FILE", None) or os.path.join(
        RES_ROOT_PATH, "analyzed_allocation_locations.txt"
    )
    analyzed_keys = _load_analyzed_location_keys(analyzed_path)
    main_logger.info(
        "dedupe: loaded %d keys from %s", len(analyzed_keys), analyzed_path
    )

    # Start CommandCaller initialization in the background; do not block main flow
    threading.Thread(target=CommandCaller, kwargs={}, daemon=True).start()
    reader = AlterAnalyzer()
    analyzer = create_analyzer()

    global_idx = 0
    skipped = 0
    skipped_session_dup = 0
    concluded = 0
    # 本次进程内已处理过的警报位置（与 analyzed_keys 互补：避免同批多文件中重复 fl:ln 多次调用模型）
    session_seen_loc_keys = set()

    for sar_path in sar_paths:
        alter_list = reader.read_alter_file(sar_path)
        alter_num = len(alter_list)
        main_logger.info("file %s — %d alerts", sar_path, alter_num)
        for i in range(alter_num):
            global_idx += 1
            alter = alter_list[i]
            loc_key = _alter_location_key(alter)
            if loc_key and loc_key in analyzed_keys:
                skipped += 1
                main_logger.info(
                    "skip (already analyzed) [%s] file %s index %d/%d",
                    loc_key,
                    os.path.basename(sar_path),
                    i + 1,
                    alter_num,
                )
                continue
            if loc_key and loc_key in session_seen_loc_keys:
                skipped_session_dup += 1
                main_logger.info(
                    "skip (duplicate alert location this run) [%s] file %s index %d/%d",
                    loc_key,
                    os.path.basename(sar_path),
                    i + 1,
                    alter_num,
                )
                continue
            if loc_key:
                session_seen_loc_keys.add(loc_key)
            main_logger.info(
                "analysing global %d — %s index %d/%d",
                global_idx,
                os.path.basename(sar_path),
                i + 1,
                alter_num,
            )
            had_conclusion = analyzer.responseForAlter(alter)
            if had_conclusion is True and loc_key:
                analyzed_keys.add(loc_key)
                _append_analyzed_location(analyzed_path, loc_key)
                concluded += 1
            elif not loc_key:
                main_logger.warning(
                    "no alert location key (fl:ln) for alter in %s", sar_path
                )

    main_logger.info(
        "done: concluded=%d skipped_already_analyzed=%d skipped_session_dup_loc=%d analyzed_path=%s",
        concluded,
        skipped,
        skipped_session_dup,
        analyzed_path,
    )

    # After analysis completes, explicitly ask graph-reader to exit
    try:
        caller = CommandCaller()
        caller.send_query({"command": "exit"})
    except Exception:
        pass

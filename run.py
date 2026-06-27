import logging
import os
import sys
from datetime import datetime

from config import *
import config as _cfg
from utils import *

from alter_handler import AlterAnalyzer
from free_analyzer import create_analyzer
from command_caller import CommandCaller
from slice_handler import (
    enrich_alerts_with_slices,
    alert_passes_source_filter,
    alert_passes_focus_filter,
)
from uaf_cluster import cluster_uaf_alerts_by_free_location
from uninit_cluster import is_uninit_sar, replace_uninit_with_slice_groups


def _load_dotenv(path: str):
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            key, _, val = s.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


def _txt_files_in_dir(d):
    names = sorted(
        f
        for f in os.listdir(d)
        if f.lower().endswith(".txt")
        and os.path.isfile(os.path.join(d, f))
        and not f.lower().endswith(".meta.txt")
        and f.startswith("svf_")
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


def _normalize_sar_path_list(raw_paths):
    """Expand user/config paths to absolute .txt SAR file paths."""
    out = []
    for p in raw_paths or []:
        s = str(p).strip()
        if not s:
            continue
        out.append(os.path.abspath(os.path.expanduser(s)))
    return out


def _resolve_sar_paths():
    """
    Resolve SAR inputs with priority:
      1) SAR_PATHS — explicit list of warning .txt files
      2) SAR_BATCH_DIRS / SAR_BATCH_DIR — scan dirs for svf_*.txt
      3) SAR_PATH — single file
    """
    explicit = _normalize_sar_path_list(getattr(_cfg, "SAR_PATHS", None))
    if explicit:
        return explicit, True

    paths = []
    for d in _effective_batch_dir_list():
        if d and os.path.isdir(d):
            paths.extend(_txt_files_in_dir(d))
    if paths:
        return paths, True

    sar_path = getattr(_cfg, "SAR_PATH", None) or ""
    sar_path = str(sar_path).strip()
    if sar_path:
        return [os.path.abspath(os.path.expanduser(sar_path))], False
    return [], False


def _run_log_stem_for_sar_paths(paths):
    if not paths:
        return "sar-list"
    if len(paths) == 1:
        return os.path.splitext(os.path.basename(paths[0]))[0] or "sar"
    stems = [os.path.splitext(os.path.basename(p))[0] for p in paths]
    if len(stems) <= 3:
        return "-".join(stems)
    return f"{stems[0]}-and-{len(stems) - 1}-more"


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


def _dedup_category(alter):
    """
    Dedup category for alert keys. Saber leak/dfree share defect_type MemoryLeak but
    must not dedupe across PartialLeak / DoubleFree / NeverFree at the same alloc site.
    """
    if hasattr(alter, "get_group_key") and callable(alter.get_group_key):
        gk = alter.get_group_key()
        if gk:
            return f"UninitUseGroup|{gk}"
    if hasattr(alter, "get_leak_type") and callable(alter.get_leak_type):
        leak_type = alter.get_leak_type()
        if leak_type:
            return str(leak_type).strip()
    defect_type = (
        alter.get_defect_type()
        if hasattr(alter, "get_defect_type")
        else getattr(alter, "defect_type", None)
    )
    return (str(defect_type).strip() if defect_type is not None else "") or "UnknownDefect"


def _alter_location_key(alter):
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc") and alter.get_source_loc()
        else None
    )
    base_loc = location_string_from_source_loc(loc)
    if not base_loc:
        return None
    category = _dedup_category(alter)
    return f"{category}|{base_loc}"


def _alter_location_key_legacy(alter):
    """兼容历史去重文件中的旧键格式：仅 fl:ln。"""
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc") and alter.get_source_loc()
        else None
    )
    return location_string_from_source_loc(loc)


def _already_analyzed(loc_key, legacy_loc_key, category, analyzed_keys):
    if loc_key and loc_key in analyzed_keys:
        return True
    if not legacy_loc_key:
        return False
    # 旧版 saber leak/dfree 统一写入 MemoryLeak|fl:ln，无法区分 PartialLeak vs DoubleFree。
    # 仅对 DoubleFree/NeverFree 保守跳过；PartialLeak 必须单独分析。
    legacy_ml_key = f"MemoryLeak|{legacy_loc_key}"
    if category in ("DoubleFree", "NeverFree") and legacy_ml_key in analyzed_keys:
        return True
    return legacy_loc_key in analyzed_keys


def _validate_sar_paths(paths, logger):
    """启动前检查：路径存在且为普通文件。"""
    missing = [p for p in paths if not os.path.isfile(p)]
    if missing:
        for p in missing:
            logger.error("SAR 不存在或不是文件: %s", p)
        return False
    if not paths:
        logger.error("SAR 列表为空")
        return False
    return True


if __name__ == "__main__":
    _load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    batch_dirs = [
        d
        for d in _effective_batch_dir_list()
        if d and os.path.isdir(d)
    ]
    sar_paths, sar_paths_from_batch = _resolve_sar_paths()
    if sar_paths_from_batch:
        _cfg.RUN_SESSION_TIME_STR = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        if not getattr(_cfg, "RUN_LOG_STEM", None):
            if _normalize_sar_path_list(getattr(_cfg, "SAR_PATHS", None)):
                _cfg.RUN_LOG_STEM = _run_log_stem_for_sar_paths(sar_paths)
            elif batch_dirs:
                _cfg.RUN_LOG_STEM = _run_log_stem_for_batch_dirs(batch_dirs)

    main_logger = setup_logger(log_type="main")
    main_logger.info("start")
    main_logger.info("SAR files: %s", sar_paths)
    if not _validate_sar_paths(sar_paths, main_logger):
        sys.exit(1)

    analyzed_path = getattr(_cfg, "ANALYZED_LOCATIONS_FILE", None) or os.path.join(
        RES_ROOT_PATH, "analyzed_allocation_locations.txt"
    )
    analyzed_keys = _load_analyzed_location_keys(analyzed_path)
    main_logger.info(
        "dedupe: loaded %d keys from %s", len(analyzed_keys), analyzed_path
    )

    graph_caller = CommandCaller()
    reader = AlterAnalyzer()
    analyzer = create_analyzer()

    global_idx = 0
    skipped = 0
    skipped_session_dup = 0
    concluded = 0
    # 本次进程内已处理过的警报位置（与 analyzed_keys 互补：避免同批多文件中重复 fl:ln 多次调用模型）
    session_seen_loc_keys = set()

    for sar_path in sar_paths:
        # 1) 读取缺陷条目
        alter_list = reader.read_alter_file(sar_path)
        slice_dir = getattr(_cfg, "SLICE_DIR", None) or None
        include_paths = getattr(_cfg, "SOURCE_PATH_INCLUDE", None) or None
        focus_locs = getattr(_cfg, "EXPERIMENT_FOCUS_LOCATIONS", None) or None
        focus_tol = int(getattr(_cfg, "EXPERIMENT_FOCUS_TOLERANCE", 0) or 0)
        max_per_file = int(getattr(_cfg, "EXPERIMENT_MAX_ALERTS_PER_FILE", 0) or 0)
        if include_paths:
            alter_list = [
                a for a in alter_list if alert_passes_source_filter(a, include_paths)
            ]
        if focus_locs:
            alter_list = [
                a
                for a in alter_list
                if alert_passes_focus_filter(a, focus_locs, focus_tol)
            ]
        if max_per_file > 0:
            alter_list = alter_list[:max_per_file]
        if getattr(_cfg, "UNINIT_GROUP_FROM_SLICES", True) and is_uninit_sar(sar_path):
            before = len(alter_list)
            alter_list = replace_uninit_with_slice_groups(
                alter_list,
                sar_path,
                slice_dir,
                include_substrings=include_paths,
                max_samples=int(getattr(_cfg, "UNINIT_GROUP_MAX_SAMPLE_SLICES", 5) or 5),
            )
            main_logger.info(
                "uninit group-from-slices: %s -> %d group alert(s)",
                before,
                len(alter_list),
            )
        if getattr(_cfg, "UAF_CLUSTER_BY_FREE_LOCATION", True):
            before = len(alter_list)
            uaf_raw = sum(
                1
                for a in alter_list
                if (a.get_defect_type() if hasattr(a, "get_defect_type") else None)
                == "UseAfterFree"
            )
            alter_list = cluster_uaf_alerts_by_free_location(alter_list)
            uaf_clustered = sum(
                1
                for a in alter_list
                if (a.get_defect_type() if hasattr(a, "get_defect_type") else None)
                == "UseAfterFree"
            )
            main_logger.info(
                "uaf cluster by free site: %d alerts (%d uaf raw) -> %d alerts (%d uaf clustered)",
                before,
                uaf_raw,
                len(alter_list),
                uaf_clustered,
            )
        skip_slice_enrich = (
            getattr(_cfg, "UNINIT_GROUP_FROM_SLICES", True) and is_uninit_sar(sar_path)
        )
        slice_matched = (
            0
            if skip_slice_enrich
            else enrich_alerts_with_slices(alter_list, sar_path, slice_dir)
        )
        if skip_slice_enrich:
            slice_matched = sum(
                1 for a in alter_list if getattr(a, "get_slice_context", lambda: None)()
            )
        alter_num = len(alter_list)
        main_logger.info(
            "file %s — %d alerts (%d with slice context)",
            sar_path,
            alter_num,
            slice_matched,
        )

        # 2) 去重：历史已分析 + 本次运行内同位置只保留一条待分析
        pending = []
        for i in range(alter_num):
            global_idx += 1
            alter = alter_list[i]
            loc_key = _alter_location_key(alter)
            legacy_loc_key = _alter_location_key_legacy(alter)
            category = _dedup_category(alter)
            if loc_key and _already_analyzed(
                loc_key, legacy_loc_key, category, analyzed_keys
            ):
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
            pending.append((global_idx, i, alter, loc_key))
            if loc_key:
                session_seen_loc_keys.add(loc_key)

        if not pending:
            main_logger.info(
                "file %s — no alerts to analyze after dedupe; skip graph-reader / LLM",
                os.path.basename(sar_path),
            )
            continue

        # 3) 有待分析项：启动 graph-reader（按 SAR 解析 .bc），再跑 LLM Agent
        bc_path = graph_caller.ensure_bitcode_for_sar(sar_path)
        main_logger.info(
            "bitcode for %s -> %s (%d alert(s) to analyze)",
            sar_path,
            bc_path,
            len(pending),
        )
        for gidx, i, alter, loc_key in pending:
            main_logger.info(
                "analysing global %d — %s index %d/%d",
                gidx,
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

    # 若曾启动 graph-reader，优雅退出（避免 send_query 在未启动时尝试拉起进程）
    try:
        CommandCaller()._cleanup_process()
    except Exception:
        pass

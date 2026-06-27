import argparse
import logging
import os
import sys
from datetime import datetime

from config import *
import config as _cfg
from utils import *

from alter_handler import AlterAnalyzer
from alert_stats import (
    aggregate_stats,
    load_analyzed_location_keys,
    prepare_sar_alerts,
    print_stats_report,
    write_stats_json,
)
from command_caller import CommandCaller


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


def _append_analyzed_location(path, key):
    if not key:
        return
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(key + "\n")


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


def _parse_cli_args():
    parser = argparse.ArgumentParser(description="FPhandler SAR 告警研判 / 条目统计")
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="只统计告警条目（不启动 graph-reader / LLM）",
    )
    return parser.parse_args()


def _stats_only_enabled(cli_stats_only: bool) -> bool:
    return cli_stats_only or bool(getattr(_cfg, "STATS_ONLY", False))


if __name__ == "__main__":
    cli_args = _parse_cli_args()
    stats_only = _stats_only_enabled(cli_args.stats_only)

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
    main_logger.info("start%s", " (stats-only)" if stats_only else "")
    main_logger.info("SAR files: %s", sar_paths)
    if not _validate_sar_paths(sar_paths, main_logger):
        sys.exit(1)

    analyzed_path = getattr(_cfg, "ANALYZED_LOCATIONS_FILE", None) or os.path.join(
        RES_ROOT_PATH, "analyzed_allocation_locations.txt"
    )
    analyzed_keys = load_analyzed_location_keys(analyzed_path)
    main_logger.info(
        "dedupe: loaded %d keys from %s", len(analyzed_keys), analyzed_path
    )

    reader = AlterAnalyzer()
    analyzer = None
    graph_caller = None
    if not stats_only:
        from free_analyzer import create_analyzer

        graph_caller = CommandCaller()
        analyzer = create_analyzer()

    global_idx = 0
    skipped = 0
    skipped_session_dup = 0
    concluded = 0
    session_seen_loc_keys = set()
    all_file_stats = []

    for sar_path in sar_paths:
        prepared = prepare_sar_alerts(
            sar_path,
            reader,
            _cfg,
            analyzed_keys,
            session_seen_loc_keys,
            logger=main_logger,
        )
        all_file_stats.append(prepared.stats)
        skipped += prepared.stats.skip_analyzed
        skipped_session_dup += prepared.stats.skip_session_dup

        alter_num = len(prepared.alter_list)
        pending = prepared.pending

        if stats_only:
            continue

        if not pending:
            main_logger.info(
                "file %s — no alerts to analyze after dedupe; skip graph-reader / LLM",
                os.path.basename(sar_path),
            )
            continue

        bc_path = graph_caller.ensure_bitcode_for_sar(sar_path)
        main_logger.info(
            "bitcode for %s -> %s (%d alert(s) to analyze)",
            sar_path,
            bc_path,
            len(pending),
        )
        for i, alter, loc_key in pending:
            global_idx += 1
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

    if stats_only:
        print_stats_report(all_file_stats)
        totals = aggregate_stats(all_file_stats)
        main_logger.info(
            "stats-only done: pending=%d skip_analyzed=%d skip_session_dup=%d",
            totals.get("pending", 0),
            totals.get("skip_analyzed", 0),
            totals.get("skip_session_dup", 0),
        )
        stats_json_path = getattr(_cfg, "STATS_OUTPUT_JSON", None)
        if stats_json_path:
            write_stats_json(all_file_stats, stats_json_path)
            main_logger.info("stats JSON written to %s", stats_json_path)
    else:
        main_logger.info(
            "done: concluded=%d skipped_already_analyzed=%d skipped_session_dup_loc=%d analyzed_path=%s",
            concluded,
            skipped,
            skipped_session_dup,
            analyzed_path,
        )
        try:
            CommandCaller()._cleanup_process()
        except Exception:
            pass

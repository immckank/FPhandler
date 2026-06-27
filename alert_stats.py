"""SAR 告警条目统计：复用 run.py 预处理与去重逻辑，不启动 graph-reader / LLM。"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional, Set, TextIO

from alter_handler import AlterAnalyzer
from slice_handler import (
    alert_passes_focus_filter,
    alert_passes_source_filter,
    enrich_alerts_with_slices,
)
from uaf_cluster import cluster_uaf_alerts_by_free_location
from uninit_cluster import is_uninit_sar, replace_uninit_with_slice_groups
from utils import location_string_from_source_loc


@dataclass
class FileAlertStats:
    sar_path: str
    raw: int = 0
    after_source_filter: int = 0
    after_focus_filter: int = 0
    after_max_cap: int = 0
    after_uninit_group: int = 0
    after_uaf_cluster: int = 0
    with_slice: int = 0
    skip_analyzed: int = 0
    skip_session_dup: int = 0
    pending: int = 0
    by_defect_type: dict[str, int] = field(default_factory=dict)
    pending_by_defect_type: dict[str, int] = field(default_factory=dict)


@dataclass
class SarPrepareResult:
    alter_list: list
    slice_matched: int
    stats: FileAlertStats
    pending: list[tuple[int, Any, Optional[str]]]


def load_analyzed_location_keys(path: str) -> Set[str]:
    if not path or not os.path.isfile(path):
        return set()
    keys: Set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if s:
                keys.add(s)
    return keys


def dedup_category(alter) -> str:
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


def alert_label(alter) -> str:
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


def alter_location_key(alter) -> Optional[str]:
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc") and alter.get_source_loc()
        else None
    )
    base_loc = location_string_from_source_loc(loc)
    if not base_loc:
        return None
    return f"{dedup_category(alter)}|{base_loc}"


def alter_location_key_legacy(alter) -> Optional[str]:
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc") and alter.get_source_loc()
        else None
    )
    return location_string_from_source_loc(loc)


def already_analyzed(
    loc_key: Optional[str],
    legacy_loc_key: Optional[str],
    category: str,
    analyzed_keys: Set[str],
) -> bool:
    if loc_key and loc_key in analyzed_keys:
        return True
    if not legacy_loc_key:
        return False
    legacy_ml_key = f"MemoryLeak|{legacy_loc_key}"
    if category in ("DoubleFree", "NeverFree") and legacy_ml_key in analyzed_keys:
        return True
    return legacy_loc_key in analyzed_keys


def count_by_label(alter_list: Iterable) -> dict[str, int]:
    return dict(Counter(alert_label(a) for a in alter_list))


def prepare_sar_alerts(
    sar_path: str,
    reader: AlterAnalyzer,
    cfg,
    analyzed_keys: Set[str],
    session_seen_loc_keys: Set[str],
    logger=None,
) -> SarPrepareResult:
    """解析单个 SAR：过滤、聚类、slice 关联、去重，返回待分析项与统计。"""
    alter_list = reader.read_alter_file(sar_path)
    stats = FileAlertStats(sar_path=sar_path, raw=len(alter_list))

    slice_dir = getattr(cfg, "SLICE_DIR", None) or None
    include_paths = getattr(cfg, "SOURCE_PATH_INCLUDE", None) or None
    focus_locs = getattr(cfg, "EXPERIMENT_FOCUS_LOCATIONS", None) or None
    focus_tol = int(getattr(cfg, "EXPERIMENT_FOCUS_TOLERANCE", 0) or 0)
    max_per_file = int(getattr(cfg, "EXPERIMENT_MAX_ALERTS_PER_FILE", 0) or 0)

    if include_paths:
        alter_list = [
            a for a in alter_list if alert_passes_source_filter(a, include_paths)
        ]
    stats.after_source_filter = len(alter_list)

    if focus_locs:
        alter_list = [
            a
            for a in alter_list
            if alert_passes_focus_filter(a, focus_locs, focus_tol)
        ]
    stats.after_focus_filter = len(alter_list)

    if max_per_file > 0:
        alter_list = alter_list[:max_per_file]
    stats.after_max_cap = len(alter_list)

    if getattr(cfg, "UNINIT_GROUP_FROM_SLICES", True) and is_uninit_sar(sar_path):
        before = len(alter_list)
        alter_list = replace_uninit_with_slice_groups(
            alter_list,
            sar_path,
            slice_dir,
            include_substrings=include_paths,
            max_samples=int(getattr(cfg, "UNINIT_GROUP_MAX_SAMPLE_SLICES", 5) or 5),
        )
        if logger:
            logger.info(
                "uninit group-from-slices: %s -> %d group alert(s)",
                before,
                len(alter_list),
            )
    stats.after_uninit_group = len(alter_list)

    if getattr(cfg, "UAF_CLUSTER_BY_FREE_LOCATION", True):
        before = len(alter_list)
        uaf_raw = sum(1 for a in alter_list if alert_label(a) == "UseAfterFree")
        alter_list = cluster_uaf_alerts_by_free_location(alter_list)
        uaf_clustered = sum(1 for a in alter_list if alert_label(a) == "UseAfterFree")
        if logger:
            logger.info(
                "uaf cluster by free site: %d alerts (%d uaf raw) -> %d alerts (%d uaf clustered)",
                before,
                uaf_raw,
                len(alter_list),
                uaf_clustered,
            )
    stats.after_uaf_cluster = len(alter_list)
    stats.by_defect_type = count_by_label(alter_list)

    skip_slice_enrich = (
        getattr(cfg, "UNINIT_GROUP_FROM_SLICES", True) and is_uninit_sar(sar_path)
    )
    if skip_slice_enrich:
        slice_matched = sum(
            1 for a in alter_list if getattr(a, "get_slice_context", lambda: None)()
        )
    else:
        slice_matched = enrich_alerts_with_slices(alter_list, sar_path, slice_dir)
    stats.with_slice = slice_matched

    if logger:
        logger.info(
            "file %s — %d alerts (%d with slice context)",
            sar_path,
            len(alter_list),
            slice_matched,
        )

    pending: list[tuple[int, Any, Optional[str]]] = []
    alter_num = len(alter_list)
    for i in range(alter_num):
        alter = alter_list[i]
        loc_key = alter_location_key(alter)
        legacy_loc_key = alter_location_key_legacy(alter)
        category = dedup_category(alter)
        if loc_key and already_analyzed(
            loc_key, legacy_loc_key, category, analyzed_keys
        ):
            stats.skip_analyzed += 1
            if logger:
                logger.info(
                    "skip (already analyzed) [%s] file %s index %d/%d",
                    loc_key,
                    os.path.basename(sar_path),
                    i + 1,
                    alter_num,
                )
            continue
        if loc_key and loc_key in session_seen_loc_keys:
            stats.skip_session_dup += 1
            if logger:
                logger.info(
                    "skip (duplicate alert location this run) [%s] file %s index %d/%d",
                    loc_key,
                    os.path.basename(sar_path),
                    i + 1,
                    alter_num,
                )
            continue
        pending.append((i, alter, loc_key))
        if loc_key:
            session_seen_loc_keys.add(loc_key)

    stats.pending = len(pending)
    stats.pending_by_defect_type = count_by_label(alter for _, alter, _ in pending)

    return SarPrepareResult(
        alter_list=alter_list,
        slice_matched=slice_matched,
        stats=stats,
        pending=pending,
    )


def aggregate_stats(file_stats: list[FileAlertStats]) -> dict[str, int]:
    totals = Counter()
    for fs in file_stats:
        totals["raw"] += fs.raw
        totals["after_source_filter"] += fs.after_source_filter
        totals["after_focus_filter"] += fs.after_focus_filter
        totals["after_max_cap"] += fs.after_max_cap
        totals["after_uninit_group"] += fs.after_uninit_group
        totals["after_uaf_cluster"] += fs.after_uaf_cluster
        totals["with_slice"] += fs.with_slice
        totals["skip_analyzed"] += fs.skip_analyzed
        totals["skip_session_dup"] += fs.skip_session_dup
        totals["pending"] += fs.pending
    return dict(totals)


def aggregate_by_defect_type(
    file_stats: list[FileAlertStats], pending: bool = False
) -> dict[str, int]:
    key = "pending_by_defect_type" if pending else "by_defect_type"
    merged: Counter = Counter()
    for fs in file_stats:
        merged.update(getattr(fs, key))
    return dict(merged)


def stats_to_dict(file_stats: list[FileAlertStats]) -> dict[str, Any]:
    return {
        "files": [asdict(fs) for fs in file_stats],
        "totals": aggregate_stats(file_stats),
        "by_defect_type": aggregate_by_defect_type(file_stats, pending=False),
        "pending_by_defect_type": aggregate_by_defect_type(file_stats, pending=True),
    }


def print_stats_report(
    file_stats: list[FileAlertStats],
    stream: TextIO | None = None,
) -> None:
    out = stream or __import__("sys").stdout
    totals = aggregate_stats(file_stats)
    pending_by_type = aggregate_by_defect_type(file_stats, pending=True)

    out.write("\n=== Alert Stats (no LLM) ===\n")
    for fs in file_stats:
        out.write(f"\nSAR: {fs.sar_path}\n")
        out.write(
            f"  raw={fs.raw} -> source_filter={fs.after_source_filter}"
            f" -> focus_filter={fs.after_focus_filter}"
            f" -> max_cap={fs.after_max_cap}\n"
        )
        out.write(
            f"  uninit_group={fs.after_uninit_group}"
            f" -> uaf_cluster={fs.after_uaf_cluster}"
            f" (with_slice={fs.with_slice})\n"
        )
        out.write(
            f"  skip(analyzed)={fs.skip_analyzed}"
            f"  skip(session_dup)={fs.skip_session_dup}"
            f"  pending={fs.pending}\n"
        )
        if fs.by_defect_type:
            type_parts = ", ".join(
                f"{k}={v}" for k, v in sorted(fs.by_defect_type.items())
            )
            out.write(f"  by_type: {type_parts}\n")
        if fs.pending_by_defect_type:
            pending_parts = ", ".join(
                f"{k}={v}" for k, v in sorted(fs.pending_by_defect_type.items())
            )
            out.write(f"  pending_by_type: {pending_parts}\n")

    out.write("\n--- TOTAL ---\n")
    out.write(
        f"  raw={totals.get('raw', 0)}"
        f" -> clustered={totals.get('after_uaf_cluster', 0)}"
        f"  pending={totals.get('pending', 0)} (estimated LLM calls)\n"
    )
    if pending_by_type:
        type_parts = ", ".join(
            f"{k}={v}" for k, v in sorted(pending_by_type.items())
        )
        out.write(f"  pending_by_type: {type_parts}\n")
    out.write("\n")


def write_stats_json(file_stats: list[FileAlertStats], path: str) -> None:
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats_to_dict(file_stats), f, ensure_ascii=False, indent=2)
        f.write("\n")

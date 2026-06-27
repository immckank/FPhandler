"""Cluster uninit downstream work to SVF slice JSON groups (one LLM call per group)."""

import json
import os
import re

from memory_defect import UninitUseGroup
from slice_handler import format_slice_for_prompt, resolve_slice_json_for_sar
from utils import normalize_source_loc, source_loc_to_string

_CALLER_CTX_RE = re.compile(r"^(.+):(\d+)$")


def is_uninit_sar(sar_path: str) -> bool:
    return "uninit" in os.path.basename(sar_path).lower()


def parse_caller_context(raw: str):
    if not raw:
        return None
    m = _CALLER_CTX_RE.match(str(raw).strip())
    if not m:
        return None
    return normalize_source_loc({"fl": m.group(1), "ln": int(m.group(2))})


def load_slice_bundle(sar_path: str, slice_dir=None):
    path = resolve_slice_json_for_sar(sar_path, slice_dir)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _pick_representative_loc(group: dict, member_slices: list, include_substrings=None):
    include_substrings = include_substrings or []

    def _in_scope(loc):
        if not loc:
            return False
        if not include_substrings:
            return True
        fl = (loc.get("fl") or "").replace("\\", "/")
        return any(sub in fl for sub in include_substrings)

    slice_candidates = []
    for sl in member_slices:
        caller = sl.get("caller") if isinstance(sl.get("caller"), dict) else None
        if caller:
            loc = normalize_source_loc(
                {
                    "fl": caller.get("file") or caller.get("fl"),
                    "ln": caller.get("line")
                    if caller.get("line") is not None
                    else caller.get("ln"),
                }
            )
            if loc:
                slice_candidates.append(loc)
        src = sl.get("source") if isinstance(sl.get("source"), dict) else None
        if src and src.get("file") and src.get("line"):
            loc = normalize_source_loc(
                {"fl": src["file"], "ln": src["line"], "col": src.get("col")}
            )
            if loc:
                slice_candidates.append(loc)

    for loc in slice_candidates:
        if _in_scope(loc):
            return loc

    ctx_candidates = []
    for ctx in group.get("caller_contexts") or []:
        loc = parse_caller_context(ctx)
        if loc:
            ctx_candidates.append(loc)
    for loc in ctx_candidates:
        if _in_scope(loc):
            return loc

    return slice_candidates[0] if slice_candidates else (
        ctx_candidates[0] if ctx_candidates else None
    )


def _format_group_slice_context(group: dict, member_slices: list, max_samples: int = 5) -> str:
    lines = [
        f"Grouped uninit bundle: object_type={group.get('object_type', '?')}",
        f"Member slice count: {group.get('member_count', len(member_slices))}",
    ]
    callers = group.get("caller_contexts") or []
    if callers:
        lines.append("Caller contexts in project code (analyzer grouping):")
        for ctx in callers[:40]:
            lines.append(f"  - {ctx}")
        if len(callers) > 40:
            lines.append(f"  ... and {len(callers) - 40} more")
    lines.append("")
    lines.append(f"Representative slices (showing up to {max_samples}):")
    for i, sl in enumerate(member_slices[:max_samples], 1):
        lines.append(f"--- sample {i} ---")
        lines.append(format_slice_for_prompt(sl))
        lines.append("")
    return "\n".join(lines).strip()


def build_uninit_groups_from_slices(
    sar_path: str,
    slice_dir=None,
    include_substrings=None,
    max_samples: int = 5,
):
    """
    Build one UninitUseGroup per entry in slice JSON ``groups`` (typically 19).
    Ignores per-line SAR entries; downstream LLM runs once per group.
    """
    bundle = load_slice_bundle(sar_path, slice_dir)
    if not bundle:
        return []

    slices = bundle.get("slices") if isinstance(bundle.get("slices"), list) else []
    groups = bundle.get("groups") if isinstance(bundle.get("groups"), list) else []
    if not groups:
        return []

    out = []
    for idx, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        members = group.get("members") if isinstance(group.get("members"), list) else []
        member_slices = [slices[i] for i in members if 0 <= i < len(slices)]
        rep_loc = _pick_representative_loc(group, member_slices, include_substrings)
        if rep_loc is None and member_slices:
            use = member_slices[0].get("use") or {}
            rep_loc = normalize_source_loc(
                {"fl": use.get("file"), "ln": use.get("line"), "col": use.get("col")}
            )
        if rep_loc is None:
            continue

        clustered = UninitUseGroup(
            rep_loc,
            object_type=str(group.get("object_type") or f"group_{idx}"),
            member_count=int(group.get("member_count") or len(member_slices)),
            caller_contexts=list(group.get("caller_contexts") or []),
            member_slices=member_slices,
            group_index=idx,
        )
        clustered.set_slice_context(
            _format_group_slice_context(group, member_slices, max_samples=max_samples)
        )
        out.append(clustered)
    return out


def replace_uninit_with_slice_groups(
    alerts,
    sar_path: str,
    slice_dir=None,
    include_substrings=None,
    max_samples: int = 5,
):
    """Drop parsed UninitUse SAR rows; return slice-group alerts plus non-uninit alerts."""
    if not is_uninit_sar(sar_path):
        return alerts
    others = [
        a
        for a in alerts
        if (a.get_defect_type() if hasattr(a, "get_defect_type") else None) != "UninitUse"
    ]
    groups = build_uninit_groups_from_slices(
        sar_path,
        slice_dir,
        include_substrings=include_substrings,
        max_samples=max_samples,
    )
    if not groups:
        # slice JSON 缺失或无 groups 时保留原始 SAR 条目，避免静默丢弃 uninit 告警
        uninit = [
            a
            for a in alerts
            if (a.get_defect_type() if hasattr(a, "get_defect_type") else None)
            == "UninitUse"
        ]
        return others + uninit
    return others + groups

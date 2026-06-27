"""Load SaberSliceExport / BOF slice JSON and enrich parsed SAR alerts."""

import json
import os
import re

from utils import location_string_from_source_loc, normalize_source_loc, source_loc_to_string


def resolve_slice_json_for_sar(sar_path: str, slice_dir=None) -> str:
    """Map SAR txt to companion slice JSON (same stem + _slices.json)."""
    base_dir = slice_dir or os.path.dirname(os.path.abspath(sar_path))
    stem = os.path.splitext(os.path.basename(sar_path))[0]
    return os.path.join(base_dir, f"{stem}_slices.json")


def _basename(fl: str) -> str:
    return os.path.basename((fl or "").replace("\\", "/"))


def _loc_dict_from_slice_field(field):
    if not isinstance(field, dict):
        return None
    fl = field.get("file") or field.get("fl")
    ln = field.get("line") if field.get("line") is not None else field.get("ln")
    if not fl or ln is None:
        return None
    out = {"fl": fl, "ln": int(ln)}
    col = field.get("col") if field.get("col") is not None else field.get("cl")
    if col is not None:
        out["cl"] = int(col)
    return out


def _parse_path_loc(raw: str):
    if not raw:
        return None
    m = re.search(
        r'\{\s*"ln"\s*:\s*(\d+)\s*,\s*"cl"\s*:\s*(\d+)\s*,\s*"fl"\s*:\s*"([^"]+)"\s*\}',
        raw,
    )
    if m:
        return {"fl": m.group(3), "ln": int(m.group(1)), "cl": int(m.group(2))}
    m = re.search(r'\{\s*"ln"\s*:\s*(\d+)\s*,\s*"fl"\s*:\s*"([^"]+)"\s*\}', raw)
    if m:
        return {"fl": m.group(2), "ln": int(m.group(1))}
    return None


def _loc_matches(a, b) -> bool:
    if not a or not b:
        return False
    if a.get("ln") != b.get("ln"):
        return False
    return _basename(a.get("fl", "")) == _basename(b.get("fl", ""))


def _alter_candidate_locs(alter):
    locs = []
    primary = normalize_source_loc(
        alter.get_source_loc() if hasattr(alter, "get_source_loc") else None
    )
    if primary:
        locs.append(primary)

    defect_type = getattr(alter, "get_defect_type", lambda: None)() or getattr(
        alter, "defect_type", ""
    )

    if defect_type == "UseAfterFree":
        for pair in getattr(alter, "node_pairs", []) or []:
            if getattr(pair, "_free_loc", None):
                locs.append(pair._free_loc)
            for use_node in pair.get_use_nodes() if hasattr(pair, "get_use_nodes") else []:
                if getattr(use_node, "_use_loc", None):
                    locs.append(use_node._use_loc)

    if defect_type == "UninitUse":
        alloc = getattr(alter, "get_alloc_loc", lambda: None)()
        if alloc:
            locs.append(normalize_source_loc(alloc))
        for u in getattr(alter, "get_use_sites", lambda: [])():
            locs.append(normalize_source_loc(u))

    if defect_type == "DoubleFree":
        for p in getattr(alter, "double_free_paths", []) or []:
            if getattr(p, "_double_loc", None):
                locs.append(p._double_loc)

    if defect_type == "PartialLeak":
        for p in getattr(alter, "conditional_free_paths", []) or []:
            if getattr(p, "_condition_loc", None):
                locs.append(p._condition_loc)

    seen = set()
    uniq = []
    for loc in locs:
        if not loc:
            continue
        key = (_basename(loc.get("fl", "")), loc.get("ln"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(loc)
    return uniq


def _slice_candidate_locs(slice_obj: dict):
    locs = []
    for key in ("source", "use", "free", "free2"):
        loc = _loc_dict_from_slice_field(slice_obj.get(key))
        if loc:
            locs.append(loc)
    access = slice_obj.get("access")
    if isinstance(access, dict):
        loc = _loc_dict_from_slice_field(access)
        if loc:
            locs.append(loc)
    return locs


def _slice_score(alter, slice_obj: dict) -> int:
    candidates = _alter_candidate_locs(alter)
    slice_locs = _slice_candidate_locs(slice_obj)
    score = 0
    for al in candidates:
        for sl in slice_locs:
            if _loc_matches(al, sl):
                score += 10
                if al is candidates[0] and sl is slice_locs[0]:
                    score += 5
    kind = (slice_obj.get("kind") or "").upper()
    defect = (getattr(alter, "get_defect_type", lambda: None)() or "").upper()
    kind_map = {
        "USE_AFTER_FREE": "USEAFTERFREE",
        "UNINIT_USE": "UNINITUSE",
        "MEMORY_LEAK": {"NEVERFREE", "PARTIALLEAK", "MEMORYLEAK"},
        "DOUBLE_FREE": "DOUBLEFREE",
    }
    expected = kind_map.get(kind)
    if isinstance(expected, set):
        if defect.replace("_", "") in expected or defect.upper() in expected:
            score += 3
    elif expected and defect.replace("_", "").upper() == expected:
        score += 3
    if defect == "BufferOverflow" and kind in ("GEP_OOB", "BUFFER_OVERFLOW", "BOF"):
        score += 3
    return score


def match_slice_to_alter(alter, slices):
    best = None
    best_score = 0
    for s in slices:
        sc = _slice_score(alter, s)
        if sc > best_score:
            best_score = sc
            best = s
    return best if best_score > 0 else None


def _format_path_conditions(path_conditions: list) -> str:
    if not path_conditions:
        return ""
    lines = ["Path conditions along the reported slice:"]
    for i, edge in enumerate(path_conditions, 1):
        if not isinstance(edge, dict):
            continue
        loc = _parse_path_loc(edge.get("location", ""))
        cond = edge.get("condition", "")
        if loc:
            lines.append(
                f"  {i}. at {source_loc_to_string(loc['fl'], loc['ln'])}"
                f" — condition: {cond!r}"
            )
        else:
            lines.append(f"  {i}. condition: {cond!r}")
    return "\n".join(lines) + "\n"


def format_slice_for_prompt(slice_obj: dict) -> str:
    if not slice_obj:
        return ""

    parts = [
        f"Slice id: {slice_obj.get('id', 'unknown')}",
        f"Slice kind: {slice_obj.get('kind', 'unknown')}",
    ]
    if slice_obj.get("static_verdict"):
        parts.append(f"Static verdict: {slice_obj['static_verdict']}")

    src = _loc_dict_from_slice_field(slice_obj.get("source"))
    if src:
        parts.append(f"Source site: {source_loc_to_string(src['fl'], src['ln'])}")

    for label, key in (
        ("Free site", "free"),
        ("Second free site", "free2"),
        ("Use site", "use"),
    ):
        loc = _loc_dict_from_slice_field(slice_obj.get(key))
        if loc:
            parts.append(f"{label}: {source_loc_to_string(loc['fl'], loc['ln'])}")

    if slice_obj.get("leak_kind"):
        parts.append(f"Leak kind: {slice_obj['leak_kind']}")
    if slice_obj.get("source_kind"):
        parts.append(f"Source kind: {slice_obj['source_kind']}")
    if slice_obj.get("allocator"):
        parts.append(f"Allocator: {slice_obj['allocator']}")

    access = slice_obj.get("access")
    if isinstance(access, dict):
        loc = _loc_dict_from_slice_field(access)
        if loc:
            parts.append(f"Access site: {source_loc_to_string(loc['fl'], loc['ln'])}")
        if access.get("index_expr"):
            parts.append(f"Index expr: {access['index_expr']}")
        buf = slice_obj.get("buffer") or {}
        cap = buf.get("capacity") if isinstance(buf, dict) else None
        if isinstance(cap, dict):
            parts.append(
                f"Buffer capacity range: [{cap.get('lower')}, {cap.get('upper')}]"
            )

    snippet = (slice_obj.get("code_snippet") or "").strip()
    if snippet:
        parts.append("Code snippet from analyzer:\n" + snippet)

    pc = _format_path_conditions(slice_obj.get("path_conditions") or [])
    if pc:
        parts.append(pc.strip())

    return "\n".join(parts)


def load_slices_for_sar(sar_path: str, slice_dir=None):
    path = resolve_slice_json_for_sar(sar_path, slice_dir)
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    slices = data.get("slices")
    return slices if isinstance(slices, list) else []


def synthesize_slice_context_from_alter(alter) -> str:
    """When slice JSON is absent, build path context from parsed SAR fields."""
    defect_type = (
        alter.get_defect_type()
        if hasattr(alter, "get_defect_type")
        else getattr(alter, "defect_type", "")
    )
    leak_type = None
    if hasattr(alter, "get_leak_type"):
        leak_type = alter.get_leak_type()
    elif hasattr(alter, "leak_type"):
        leak_type = alter.leak_type
    label = leak_type if defect_type == "MemoryLeak" and leak_type else defect_type
    parts = [f"Synthesized slice context for {label}:"]

    if getattr(alter, "conditional_free_paths", None):
        paths = alter.conditional_free_paths
        if paths:
            parts.append("Conditional free paths:")
            for p in paths:
                parts.append(
                    f"  - at {p.get_condition_location()}: condition={p.get_condition()!r}"
                )

    if getattr(alter, "double_free_paths", None):
        paths = alter.double_free_paths
        if paths:
            parts.append("Double-free path conditions:")
            for p in paths:
                parts.append(
                    f"  - at {p.get_double_location()}: condition={p.get_condition()!r}"
                )

    if defect_type == "UseAfterFree":
        pairs = getattr(alter, "node_pairs", None) or []
        for i, pair in enumerate(pairs, 1):
            parts.append(f"Free-use pair {i}: free at {pair.get_free_location()}")
            for use_node in pair.get_use_nodes():
                line = f"  - use at {use_node.get_use_location()}"
                cond = use_node.get_condition()
                cond_loc = use_node.get_condition_location()
                if cond and cond_loc:
                    line += f" (condition {cond!r} at {cond_loc})"
                parts.append(line)

    elif defect_type == "UninitUse":
        alloc = (
            alter.get_alloc_loc() if hasattr(alter, "get_alloc_loc") else None
        )
        if alloc:
            parts.append(
                f"Allocation site: {source_loc_to_string(alloc['fl'], alloc['ln'])}"
            )
        uses = alter.get_use_sites() if hasattr(alter, "get_use_sites") else []
        if uses:
            parts.append("Use site(s):")
            for u in uses:
                parts.append(f"  - {source_loc_to_string(u['fl'], u['ln'])}")
        paths = getattr(alter, "get_path_conditions", lambda: [])()
        if paths:
            parts.append("Path conditions:")
            for cond, loc in paths:
                parts.append(
                    f"  - at {source_loc_to_string(loc['fl'], loc['ln'])}: {cond!r}"
                )

    elif defect_type == "BufferOverflow":
        if getattr(alter, "buffer_index_text", None):
            parts.append(f"Access range: {alter.buffer_index_text}")
        if getattr(alter, "buffer_size_text", None):
            parts.append(f"Valid range: {alter.buffer_size_text}")
        if getattr(alter, "ir_instruction", None):
            parts.append(f"IR: {alter.ir_instruction}")

    if len(parts) <= 1:
        return ""
    return "\n".join(parts)


def enrich_alerts_with_slices(alter_list, sar_path: str, slice_dir=None):
    slices = load_slices_for_sar(sar_path, slice_dir)
    matched = 0
    for alter in alter_list:
        if not hasattr(alter, "set_slice_context"):
            continue
        sl = match_slice_to_alter(alter, slices) if slices else None
        if sl:
            alter.set_slice_context(format_slice_for_prompt(sl))
            matched += 1
            continue
        synth = synthesize_slice_context_from_alter(alter)
        if synth:
            alter.set_slice_context(synth)
            matched += 1
    return matched


def alert_passes_source_filter(alter, include_substrings):
    if not include_substrings:
        return True
    loc = (
        alter.get_source_loc()
        if hasattr(alter, "get_source_loc")
        else getattr(alter, "_source_loc", None)
    )
    fl = (loc or {}).get("fl", "") if isinstance(loc, dict) else ""
    fl = fl.replace("\\", "/")
    return any(sub in fl for sub in include_substrings)


def alert_passes_focus_filter(alter, focus_locations, tolerance=0):
    if not focus_locations:
        return True
    candidates = _alter_candidate_locs(alter)
    if not candidates:
        return False
    tol = max(0, int(tolerance or 0))
    for loc in candidates:
        fl = _basename(loc.get("fl", ""))
        ln = loc.get("ln")
        if ln is None:
            continue
        for seed_fl, seed_ln in focus_locations:
            if fl == _basename(seed_fl) or fl.endswith(seed_fl):
                if abs(int(ln) - int(seed_ln)) <= tol:
                    return True
    return False

"""Cluster UseAfterFree alerts by unique free site (fl:ln)."""

from memory_defect import UseAfterFree
from utils import normalize_source_loc, source_loc_to_string


def _free_key(free_loc):
    loc = normalize_source_loc(free_loc)
    if not loc:
        return None
    return (loc["fl"], loc["ln"])


def _use_key(use_node):
    loc = getattr(use_node, "_use_loc", None)
    loc = normalize_source_loc(loc)
    if not loc:
        return None
    return (loc["fl"], loc["ln"])


def cluster_uaf_alerts_by_free_location(alerts):
    """
    Merge UAF alerts that share the same free site into one alert per unique free location.
    The clustered alert uses the free site as source_loc for dedup and graph-reader queries.
    """
    out = []
    buckets = {}

    for alter in alerts:
        defect_type = (
            alter.get_defect_type()
            if hasattr(alter, "get_defect_type")
            else getattr(alter, "defect_type", None)
        )
        if defect_type != "UseAfterFree":
            out.append(alter)
            continue

        alloc_loc = (
            alter.get_source_loc()
            if hasattr(alter, "get_source_loc")
            else None
        )
        alloc_key = _free_key(alloc_loc) if alloc_loc else None

        for pair in alter.get_node_pairs() if hasattr(alter, "get_node_pairs") else []:
            key = _free_key(getattr(pair, "_free_loc", None))
            if not key:
                continue
            bucket = buckets.setdefault(
                key,
                {
                    "free_loc": normalize_source_loc(pair._free_loc),
                    "use_nodes": {},
                    "alloc_locs": set(),
                },
            )
            if alloc_key:
                bucket["alloc_locs"].add(alloc_key)
            for use_node in pair.get_use_nodes() if hasattr(pair, "get_use_nodes") else []:
                uk = _use_key(use_node)
                if uk and uk not in bucket["use_nodes"]:
                    bucket["use_nodes"][uk] = use_node

    for bucket in buckets.values():
        uses = list(bucket["use_nodes"].values())
        free_loc = bucket["free_loc"]
        pair = UseAfterFree.NodePair(free_loc, uses)
        clustered = UseAfterFree(free_loc, [pair])
        clustered._alloc_sources = sorted(
            source_loc_to_string(fl, ln) for fl, ln in bucket["alloc_locs"]
        )
        out.append(clustered)

    return out

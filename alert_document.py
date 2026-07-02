"""Unified one-file-per-alert document used by the Saber pipeline."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable

VALID_CLASSIFICATIONS = {"TP", "FP", "UNCERTAIN"}


def _path_nodes(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    path = document.get("path")
    if isinstance(path, list):
        yield from (node for node in path if isinstance(node, dict))
    allocation = document.get("allocation")
    if isinstance(allocation, dict):
        yield allocation
    for safe_path in document.get("paths") or []:
        if isinstance(safe_path, dict):
            yield from (
                node
                for node in safe_path.get("path") or []
                if isinstance(node, dict)
            )


def _location(location: dict[str, Any]) -> dict[str, Any]:
    return {
        "fl": str(location["file"]),
        "ln": int(location["line"]),
        "cl": int(location.get("column") or 0),
    }


def _path_location(document: dict[str, Any]) -> dict[str, Any]:
    preferred = ("use", "second_free", "free", "first_free", "allocation", "object_origin")
    nodes = list(_path_nodes(document))
    for role in preferred:
        for node in reversed(nodes):
            location = node.get("location")
            if node.get("role") == role and isinstance(location, dict):
                return _location(location)
    raise KeyError(f"no primary location for {document['alert_id']}")


def _bof_location(document: dict[str, Any]) -> dict[str, Any]:
    return _location(document["access"]["location"])


def _single_alert_batch(document: dict[str, Any]) -> tuple:
    return document["category"], document["alert_id"]


def _uaf_batch(document: dict[str, Any]) -> tuple:
    free = next(node for node in document["path"] if node["role"] == "free")
    location = free["location"]
    return document["category"], location["file"], int(location["line"])


def _uninit_batch(document: dict[str, Any]) -> tuple:
    memory = document["evidence"]["memory_object"]
    return document["category"], memory["type"] or memory["descriptor"]


def _bof_batch(document: dict[str, Any]) -> tuple:
    return document["category"], document["access"]["kind"]


@dataclass(frozen=True)
class CategoryBehavior:
    primary_location: Callable[[dict[str, Any]], dict[str, Any]]
    batch_key: Callable[[dict[str, Any]], tuple]
    prompt_hint: str


PATH_HINT = (
    "`path` is a pruned SVFG value-flow witness; branch entries carry the "
    "required control outcome."
)
CATEGORY_BEHAVIORS = {
    "MEMORY_LEAK": CategoryBehavior(
        _path_location,
        _single_alert_batch,
        "`paths` are possible safe freeing witnesses and `leak_condition` is "
        "the complement that constitutes danger.",
    ),
    "DOUBLE_FREE": CategoryBehavior(_path_location, _single_alert_batch, PATH_HINT),
    "USE_AFTER_FREE": CategoryBehavior(_path_location, _uaf_batch, PATH_HINT),
    "UNINIT_USE": CategoryBehavior(_path_location, _uninit_batch, PATH_HINT),
    "BUFFER_OVERFLOW": CategoryBehavior(
        _bof_location,
        _bof_batch,
        "`range_analysis` is the ordered value-range derivation from variables "
        "and guards through the final bounds comparison.",
    ),
}


def category_behavior(document: dict[str, Any]) -> CategoryBehavior:
    return CATEGORY_BEHAVIORS[document["category"]]


@dataclass
class AlertDocument:
    path: str
    data: dict[str, Any]

    @classmethod
    def load(cls, path: str) -> "AlertDocument":
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        return cls(path=os.path.abspath(path), data=data)

    def write_classification(self, result: dict[str, Any]) -> None:
        classification = str(result["classification"])
        if classification not in VALID_CLASSIFICATIONS:
            raise ValueError(f"invalid classification: {classification}")
        reason = str(result["reason"]).strip()
        self.data["classification"] = classification
        self.data["reason"] = reason
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as stream:
            json.dump(self.data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(tmp, self.path)


class UnifiedAlert:
    """Adapter exposing a unified alert to the existing analysis agent."""

    def __init__(self, document: AlertDocument):
        self.document = document
        self.defect_type = document.data["category"]
        self.behavior = category_behavior(document.data)
        self._source_loc = self.behavior.primary_location(document.data)
        self.source_location = f"{self._source_loc['fl']}:{self._source_loc['ln']}"

    def get_source_loc(self):
        return self._source_loc

    def get_defect_type(self):
        return self.defect_type

    def to_prompt(self, agent_id: str | None = None) -> str:
        data = dict(self.document.data)
        if agent_id is not None:
            # The canonical SHA-256 remains on disk for stable cross-run identity.
            # The model only needs a short, unambiguous ID within this batch.
            data["alert_id"] = agent_id
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        return (
            "Classify this SVFmemplus static-analysis alert. "
            f"{self.behavior.prompt_hint}\n\n"
            f"{payload}"
        )

    def to_goal_prompt(self) -> str:
        return (
            f"Determine whether alert {self.document.data['alert_id']} is a real "
            f"{self.document.data['category']} defect."
        )

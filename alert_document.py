"""Unified one-file-per-alert document used by the Saber pipeline."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

VALID_CATEGORIES = {
    "MEMORY_LEAK",
    "DOUBLE_FREE",
    "USE_AFTER_FREE",
    "UNINIT_USE",
}
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


def primary_location(document: dict[str, Any]) -> dict[str, Any] | None:
    preferred = ("use", "second_free", "free", "first_free", "allocation", "object_origin")
    nodes = list(_path_nodes(document))
    for role in preferred:
        for node in reversed(nodes):
            location = node.get("location")
            if node.get("role") == role and isinstance(location, dict):
                if location.get("file") and int(location.get("line") or 0) > 0:
                    return {
                        "fl": str(location["file"]),
                        "ln": int(location["line"]),
                        "cl": int(location.get("column") or 0),
                    }
    return None


def validate_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document must be an object"]
    alert_id = document.get("alert_id")
    if not isinstance(alert_id, str) or not alert_id.startswith("sha256:"):
        errors.append("alert_id must start with sha256:")
    category = document.get("category")
    if category not in VALID_CATEGORIES:
        errors.append(f"unsupported category: {category!r}")
    if category == "MEMORY_LEAK":
        if not isinstance(document.get("allocation"), dict):
            errors.append("memory leak requires allocation")
        if not isinstance(document.get("paths"), list):
            errors.append("memory leak requires paths")
        if not isinstance(document.get("leak_condition"), dict):
            errors.append("memory leak requires leak_condition")
        if "path" in document:
            errors.append("memory leak must not contain singular path")
    else:
        if not isinstance(document.get("path"), list) or not document.get("path"):
            errors.append("non-leak alert requires one non-empty path")
        if "paths" in document:
            errors.append("non-leak alert must not contain paths")
    classification = document.get("classification")
    if classification is not None and classification not in VALID_CLASSIFICATIONS:
        errors.append(f"invalid classification: {classification!r}")
    if not isinstance(document.get("reason", ""), str):
        errors.append("reason must be a string")
    return errors


@dataclass
class AlertDocument:
    path: str
    data: dict[str, Any]

    @classmethod
    def load(cls, path: str) -> "AlertDocument":
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        errors = validate_document(data)
        if errors:
            raise ValueError("; ".join(errors))
        return cls(path=os.path.abspath(path), data=data)

    def write_classification(self, result: dict[str, Any]) -> None:
        classification = str(result.get("classification") or "UNCERTAIN")
        if classification not in VALID_CLASSIFICATIONS:
            raise ValueError(f"invalid classification: {classification}")
        reason = str(result.get("reason") or "").strip()
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
        self._source_loc = primary_location(document.data)
        self.source_location = (
            f"{self._source_loc['fl']}:{self._source_loc['ln']}"
            if self._source_loc
            else None
        )

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
            "Classify this Saber static-analysis alert. `path` is a pruned SVFG "
            "value-flow witness; branch entries carry the required control outcome. "
            "For MEMORY_LEAK, `paths` are possible safe freeing witnesses and "
            "`leak_condition` is the complement that constitutes danger.\n\n"
            f"{payload}"
        )

    def to_goal_prompt(self) -> str:
        return (
            f"Determine whether alert {self.document.data['alert_id']} is a real "
            f"{self.document.data['category']} defect."
        )

"""Validation and accumulation for conclusions returned during one agent batch."""
from __future__ import annotations

from typing import Any

VALID_CLASSIFICATIONS = {"TP", "FP", "UNCERTAIN"}


class BatchConclusions:
    def __init__(self, id_map: dict[str, str]):
        if not id_map:
            raise ValueError("batch must contain at least one alert")
        self.id_map = id_map
        self.results: dict[str, dict[str, Any]] = {}

    @property
    def missing(self) -> list[str]:
        return sorted(set(self.id_map) - set(self.results))

    @property
    def complete(self) -> bool:
        return not self.missing

    def add(self, conclusions: Any) -> dict[str, Any]:
        if not isinstance(conclusions, list) or not conclusions:
            return {"error": "results must be a non-empty array", "missing": self.missing}

        additions: dict[str, dict[str, Any]] = {}
        for conclusion in conclusions:
            if not isinstance(conclusion, dict):
                return {"error": "each result must be an object", "missing": self.missing}
            ids = conclusion.get("alert_ids")
            classification = conclusion.get("classification")
            reason = conclusion.get("reason")
            if not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids):
                return {"error": "alert_ids must be a non-empty string array", "missing": self.missing}
            if classification not in VALID_CLASSIFICATIONS or not isinstance(reason, str):
                return {"error": "invalid classification or reason", "missing": self.missing}
            for short_id in ids:
                if short_id not in self.id_map:
                    return {"error": f"unknown alert id: {short_id}", "missing": self.missing}
                if short_id in self.results or short_id in additions:
                    return {"error": f"alert id already classified: {short_id}", "missing": self.missing}
                additions[short_id] = {
                    "classification": classification,
                    "reason": reason,
                    "semantic_candidates": (
                        conclusion.get("semantic_candidates")
                        if isinstance(conclusion.get("semantic_candidates"), list)
                        else []
                    ),
                }

        self.results.update(additions)
        return {
            "accepted": sorted(additions),
            "missing": self.missing,
            "complete": self.complete,
        }

    def canonical_results(self) -> dict[str, dict[str, Any]]:
        return {
            self.id_map[short_id]: result
            for short_id, result in self.results.items()
        }

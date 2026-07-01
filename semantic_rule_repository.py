"""Append LLM semantic_candidates into a single semantic-rules/v1 repository."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from semantic_rules import ALLOWED_KINDS

_OPTIONAL_RULE_FIELDS = (
    "effect",
    "target_arg",
    "source_arg",
    "length_arg",
    "field_path",
    "pair",
    "confidence",
    "reason",
)


def _empty_repository() -> dict[str, Any]:
    return {"schema": "semantic-rules/v1", "rules": []}


def load_repository(path: str) -> dict[str, Any]:
    if not os.path.isfile(path):
        return _empty_repository()
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: repository must be a JSON object")
    if data.get("schema") != "semantic-rules/v1" or not isinstance(data.get("rules"), list):
        raise ValueError(f"{path}: expected semantic-rules/v1 with rules[]")
    return data


def stable_rule_id(candidate: dict[str, Any]) -> str:
    payload = {
        "kind": candidate.get("kind"),
        "function": candidate.get("function"),
        "match": candidate.get("match", "exact"),
    }
    for field in _OPTIONAL_RULE_FIELDS:
        if field in candidate and candidate[field] not in (None, ""):
            payload[field] = candidate[field]
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]
    return f"proposed-{candidate['kind']}-{digest}"


def candidate_to_rule(candidate: dict[str, Any], alert_id: str) -> dict[str, Any] | None:
    if not isinstance(candidate, dict):
        return None
    kind = candidate.get("kind")
    function = candidate.get("function")
    if kind not in ALLOWED_KINDS or not isinstance(function, str) or not function.strip():
        return None
    match = candidate.get("match", "exact")
    if match not in {"exact", "substring"}:
        match = "exact"
    rule: dict[str, Any] = {
        "id": stable_rule_id({**candidate, "kind": kind, "function": function, "match": match}),
        "status": "proposed",
        "kind": kind,
        "function": function.strip(),
        "match": match,
        "source_alert_id": alert_id,
        "proposed_by": "FPhandler",
    }
    for field in _OPTIONAL_RULE_FIELDS:
        if field not in candidate or candidate[field] in (None, ""):
            continue
        rule[field] = candidate[field]
    if "confidence" in rule:
        try:
            rule["confidence"] = float(rule["confidence"])
        except (TypeError, ValueError):
            rule.pop("confidence", None)
    for arg_field in ("target_arg", "source_arg", "length_arg"):
        if arg_field in rule:
            try:
                rule[arg_field] = int(rule[arg_field])
            except (TypeError, ValueError):
                rule.pop(arg_field, None)
    return rule


def append_candidates(path: str, alert_id: str, candidates: Any) -> int:
    """Append new proposed rules to path; skip duplicates by rule id."""
    if not isinstance(candidates, list) or not candidates:
        return 0
    repository = load_repository(path)
    existing_ids = {
        rule.get("id")
        for rule in repository["rules"]
        if isinstance(rule, dict) and rule.get("id")
    }
    appended = 0
    for candidate in candidates:
        rule = candidate_to_rule(candidate, alert_id)
        if rule is None or rule["id"] in existing_ids:
            continue
        repository["rules"].append(rule)
        existing_ids.add(rule["id"])
        appended += 1
    if appended == 0:
        return 0
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(repository, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(tmp, path)
    return appended

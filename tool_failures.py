"""Detect and persist tool failures during FPhandler agent runs."""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional


def _config():
    try:
        import config as cfg
    except ModuleNotFoundError:
        return None
    return cfg

_FAILURE_STRINGS = (
    "No such file, please check filename.",
    "The line number is invalid or out of range for the file.",
)


def _string_failure_kind(text: str) -> Optional[str]:
    stripped = text.strip()
    if not stripped:
        return None
    if stripped in _FAILURE_STRINGS:
        return "no_such_file" if "No such file" in stripped else "invalid_line"
    lowered = stripped.lower()
    if lowered.startswith("error:"):
        return "error_string"
    if stripped.startswith("File not found:"):
        return "file_not_found"
    if "No such file, please check filename." in stripped:
        return "no_such_file"
    return None


def classify_tool_failure(response: Any) -> Optional[dict[str, str]]:
    """Return failure metadata when a tool response indicates failure."""
    if response is None:
        return {"kind": "null_response", "detail": "tool returned None"}

    if isinstance(response, str):
        kind = _string_failure_kind(response)
        if kind:
            return {"kind": kind, "detail": response[:500]}
        return None

    if isinstance(response, dict):
        error = response.get("error")
        if isinstance(error, str) and error:
            return {"kind": "error_dict", "detail": error[:500]}
        if error not in (None, False, ""):
            return {"kind": "error_dict", "detail": str(error)[:500]}

        body = response.get("function_body")
        if isinstance(body, str):
            kind = _string_failure_kind(body)
            if kind:
                return {"kind": f"degraded_{kind}", "detail": body[:500]}
        return None

    return None


class ToolFailureRecorder:
    """Append structured tool failure records for one FPhandler session."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._path = self._build_path()

    @staticmethod
    def _build_path() -> str:
        cfg = _config()
        root = getattr(cfg, "RES_ROOT_PATH", ".") if cfg else "."
        stem = getattr(cfg, "RUN_LOG_STEM", "alerts") if cfg else "alerts"
        time_str = (
            getattr(cfg, "RUN_SESSION_TIME_STR", None) if cfg else None
        ) or datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        directory = os.path.join(root, "TOOL_FAILURES")
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, f"{stem}-{time_str}.jsonl")

    @property
    def path(self) -> str:
        return self._path

    def record(
        self,
        *,
        tool: str,
        response: Any,
        batch_id: str = "",
        turn: int = 0,
        arguments: Any = None,
        context: str = "",
    ) -> bool:
        failure = classify_tool_failure(response)
        if failure is None:
            return False

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "batch_id": batch_id,
            "turn": turn,
            "tool": tool,
            "context": context,
            "failure_kind": failure["kind"],
            "detail": failure["detail"],
            "arguments": arguments,
            "response": _compact_response(response),
        }
        self.records.append(entry)
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True

    def summary(self) -> dict[str, Any]:
        by_tool: Counter[str] = Counter()
        by_kind: Counter[str] = Counter()
        for entry in self.records:
            by_tool[entry["tool"]] += 1
            by_kind[entry["failure_kind"]] += 1
        return {
            "total": len(self.records),
            "path": self._path,
            "by_tool": dict(sorted(by_tool.items())),
            "by_kind": dict(sorted(by_kind.items())),
        }


def _compact_response(response: Any) -> Any:
    if isinstance(response, dict):
        compact = dict(response)
        for key in ("function_body",):
            value = compact.get(key)
            if isinstance(value, str) and len(value) > 300:
                compact[key] = value[:300] + "..."
        return compact
    if isinstance(response, str) and len(response) > 500:
        return response[:500] + "..."
    return response

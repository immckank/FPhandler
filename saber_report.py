"""Read/update saber-report/v2 and maintain reviewed semantic-rule candidates."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def report_path_for_sar(sar_path: str, output_dir=None) -> str:
    directory = os.path.abspath(output_dir) if output_dir else os.path.dirname(
        os.path.abspath(sar_path)
    )
    stem, _ = os.path.splitext(os.path.basename(sar_path))
    stem = os.path.join(directory, stem)
    return stem + "_report.json"


def _locations(alert):
    for key in ("source", "free", "free2", "use", "caller"):
        loc = alert.get(key)
        if isinstance(loc, dict):
            yield loc
    for node in alert.get("trace") or []:
        if isinstance(node, dict) and isinstance(node.get("location"), dict):
            yield node["location"]


class SaberReportStore:
    def __init__(self, path: str):
        self.path = path
        self.data = None
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as stream:
                candidate = json.load(stream)
            if candidate.get("schema") == "saber-report/v2":
                self.data = candidate

    def available(self):
        return self.data is not None

    def match(self, defect):
        if not self.data:
            return None
        target = defect.get_source_loc() or {}
        target_file = os.path.normpath(target.get("fl") or "")
        target_line = int(target.get("ln") or 0)
        best = None
        best_score = -1
        for record in self.data.get("alerts") or []:
            alert = record.get("alert") or {}
            score = 0
            for loc in _locations(alert):
                file_name = os.path.normpath(str(loc.get("file") or ""))
                line = int(loc.get("line") or 0)
                if target_line and line == target_line:
                    score = max(score, 2)
                    if target_file and (
                        file_name == target_file
                        or file_name.endswith(target_file)
                        or target_file.endswith(file_name)
                    ):
                        score = 4
            if score > best_score:
                best, best_score = record, score
        return best if best_score >= 2 else None

    def matching_records(self, defect):
        """Return every concrete report covered by a clustered FPhandler alert."""
        if not self.data:
            return []
        by_id = {
            (record.get("alert") or {}).get("id"): record
            for record in self.data.get("alerts") or []
        }
        member_slices = getattr(defect, "member_slices", None)
        if member_slices:
            records = [
                by_id.get(item.get("id"))
                for item in member_slices
                if isinstance(item, dict) and item.get("id")
            ]
            return [record for record in records if record is not None]

        free_locs = []
        for pair in getattr(defect, "node_pairs", None) or []:
            loc = getattr(pair, "_free_loc", None)
            if isinstance(loc, dict):
                free_locs.append((loc.get("fl"), int(loc.get("ln") or 0)))
        if free_locs:
            records = []
            for record in self.data.get("alerts") or []:
                free = (record.get("alert") or {}).get("free") or {}
                if (free.get("file"), int(free.get("line") or 0)) in free_locs:
                    records.append(record)
            if records:
                return records

        record = self.match(defect)
        return [record] if record is not None else []

    def attach_context(self, defect):
        records = self.matching_records(defect)
        if not records:
            return None
        record = records[0]
        alert = record.get("alert") or {}
        lines = [
            f"Stable alert id: {alert.get('id', 'unknown')}",
            f"Saber kind: {alert.get('kind', 'unknown')}",
            "Ordered Saber trace:",
        ]
        for node in alert.get("trace") or []:
            loc = node.get("location") or {}
            lines.append(
                f"- {node.get('role', 'path')} {node.get('function', 'unknown')} "
                f"at {loc.get('file', '')}:{loc.get('line', 0)}: "
                f"{node.get('description', '')}"
            )
        solver = record.get("solver") or {}
        lines.append(f"Solver status: {solver.get('status', 'unknown')}")
        conditions = alert.get("path_conditions") or []
        if conditions:
            lines.append("Path conditions:")
            for condition in conditions:
                lines.append(
                    f"- {condition.get('location', '')}: "
                    f"{condition.get('condition', '')}"
                )
        snippet = str(alert.get("code_snippet") or "").strip()
        if snippet:
            lines.extend(("Analyzer source window:", "```", snippet, "```"))
        defect.set_slice_context("\n".join(lines))
        return record

    def record_triage(self, record, result):
        if not self.data or not record:
            return
        analyzed_at = datetime.now(timezone.utc).isoformat()
        analysis_result = {
            "classification": result.get("classification", "UNCERTAIN"),
            "reason": result.get("reason", ""),
            "function_name": result.get("function_name", "unknown"),
        }
        record["triage"] = {
            "analysis_time": analyzed_at,
            "analysis_result": analysis_result,
            # Compatibility mirrors for existing consumers.
            **analysis_result,
            "source": "FPhandler",
        }
        candidates = result.get("semantic_candidates") or []
        record["semantic_candidates"] = candidates
        record["llm_enrichment"] = {
            "analysis_time": analyzed_at,
            "analysis_result": analysis_result,
            "semantic_facts": candidates,
            "source_context": (record.get("alert") or {}).get("code_snippet", ""),
            "path_conditions": (record.get("alert") or {}).get("path_conditions", []),
            "trace": (record.get("alert") or {}).get("trace", []),
        }
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as stream:
            json.dump(self.data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(tmp, self.path)


ALLOWED_KINDS = {
    "initializer", "memory_transfer", "allocator", "deallocator",
    "resource_open", "resource_close", "ownership_transfer",
    "heap_object_summary", "domain_hint",
}


def append_candidates(path: str, alert_id: str, candidates):
    if not candidates:
        return 0
    data = {"schema": "semantic-rules/v1", "rules": []}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as stream:
            loaded = json.load(stream)
        if loaded.get("schema") == "semantic-rules/v1":
            data = loaded
    existing = {rule.get("id") for rule in data["rules"]}
    added = 0
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict) or candidate.get("kind") not in ALLOWED_KINDS:
            continue
        function = str(candidate.get("function") or "").strip()
        if not function:
            continue
        rule = dict(candidate)
        rule_id = str(rule.get("id") or f"{rule['kind']}:{function}:{alert_id}:{index}")
        if rule_id in existing:
            continue
        rule.update({
            "id": rule_id,
            "status": "proposed",
            "source_alert_ids": [alert_id],
        })
        rule.setdefault("match", "exact")
        rule.setdefault("confidence", 0.0)
        rule.setdefault("reason", "")
        data["rules"].append(rule)
        existing.add(rule_id)
        added += 1
    if added:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return added

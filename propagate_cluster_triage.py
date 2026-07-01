"""Propagate representative FPhandler verdicts to concrete clustered alerts."""
import argparse
import json
import os


def _write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(tmp, path)


def propagate_uninit(report_path, slice_path):
    report = json.load(open(report_path, encoding="utf-8"))
    bundle = json.load(open(slice_path, encoding="utf-8"))
    records = report.get("alerts") or []
    by_id = {(r.get("alert") or {}).get("id"): r for r in records}
    slices = bundle.get("slices") or []
    updated = 0
    for group in bundle.get("groups") or []:
        members = [
            by_id.get(slices[i].get("id"))
            for i in group.get("members") or []
            if 0 <= i < len(slices)
        ]
        members = [r for r in members if r]
        verdict = next((r.get("triage") for r in members if r.get("triage")), None)
        candidates = next(
            (r.get("semantic_candidates") for r in members if r.get("triage")), []
        )
        if not verdict:
            continue
        for record in members:
            if not record.get("triage"):
                record["triage"] = dict(verdict, propagated_from_cluster=True)
                record["semantic_candidates"] = candidates or []
                updated += 1
    _write(report_path, report)
    return updated


def propagate_uaf(report_path):
    report = json.load(open(report_path, encoding="utf-8"))
    buckets = {}
    for record in report.get("alerts") or []:
        free = (record.get("alert") or {}).get("free") or {}
        buckets.setdefault((free.get("file"), free.get("line")), []).append(record)
    updated = 0
    for records in buckets.values():
        verdict = next((r.get("triage") for r in records if r.get("triage")), None)
        candidates = next(
            (r.get("semantic_candidates") for r in records if r.get("triage")), []
        )
        if not verdict:
            continue
        for record in records:
            if not record.get("triage"):
                record["triage"] = dict(verdict, propagated_from_cluster=True)
                record["semantic_candidates"] = candidates or []
                updated += 1
    _write(report_path, report)
    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uaf-report")
    parser.add_argument("--uninit-report")
    parser.add_argument("--uninit-slices")
    args = parser.parse_args()
    count = 0
    if args.uaf_report:
        count += propagate_uaf(args.uaf_report)
    if args.uninit_report and args.uninit_slices:
        count += propagate_uninit(args.uninit_report, args.uninit_slices)
    print(f"propagated triage to {count} concrete alert record(s)")


if __name__ == "__main__":
    main()

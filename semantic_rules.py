"""Validate, review and export semantic-rules/v1 repositories."""
import argparse
import json
import sys

ALLOWED_KINDS = {
    "initializer", "memory_transfer", "allocator", "deallocator",
    "resource_open", "resource_close", "ownership_transfer",
    "heap_object_summary", "domain_hint",
}


def validate(data):
    errors = []
    if data.get("schema") != "semantic-rules/v1" or not isinstance(data.get("rules"), list):
        return ["expected semantic-rules/v1 with rules[]"]
    seen = set()
    for index, rule in enumerate(data["rules"]):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix}: not an object")
            continue
        if rule.get("kind") not in ALLOWED_KINDS:
            errors.append(f"{prefix}: unsupported kind")
        if not rule.get("id") or rule.get("id") in seen:
            errors.append(f"{prefix}: missing or duplicate id")
        seen.add(rule.get("id"))
        if not rule.get("function"):
            errors.append(f"{prefix}: function is required")
        if rule.get("match", "exact") not in {"exact", "substring"}:
            errors.append(f"{prefix}: match must be exact or substring")
        if rule.get("status", "proposed") not in {"proposed", "approved", "rejected"}:
            errors.append(f"{prefix}: invalid status")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repository")
    parser.add_argument("--approve", action="append", default=[])
    parser.add_argument("--reject", action="append", default=[])
    parser.add_argument("--export-approved")
    args = parser.parse_args()
    with open(args.repository, encoding="utf-8") as stream:
        data = json.load(stream)
    errors = validate(data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    approve, reject = set(args.approve), set(args.reject)
    for rule in data["rules"]:
        if rule["id"] in approve:
            rule["status"] = "approved"
        if rule["id"] in reject:
            rule["status"] = "rejected"
    if approve or reject:
        with open(args.repository, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    if args.export_approved:
        approved = dict(data)
        approved["rules"] = [r for r in data["rules"] if r.get("status") == "approved"]
        with open(args.export_approved, "w", encoding="utf-8") as stream:
            json.dump(approved, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

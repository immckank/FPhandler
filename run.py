"""FPhandler entry point for unified one-file-per-alert Saber output."""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime


def _bootstrap_config_from_cli() -> None:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    args, _ = pre.parse_known_args()
    if not args.config:
        return
    path = os.path.abspath(os.path.expanduser(args.config))
    if not os.path.isfile(path):
        print(f"error: config 不存在: {path}", file=sys.stderr)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location("config", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["config"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)


_bootstrap_config_from_cli()

import config as _cfg
from alert_document import AlertDocument, UnifiedAlert
from command_caller import CommandCaller
from utils import setup_logger


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FPhandler unified Saber alert triage")
    parser.add_argument("--config", metavar="PATH")
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="validate and count alert JSON without graph-reader or LLM",
    )
    return parser.parse_args()


def discover_alerts(root: str) -> list[str]:
    found: list[str] = []
    if not os.path.isdir(root):
        return found
    for directory, _, files in os.walk(root):
        for filename in files:
            if filename.endswith(".json"):
                found.append(os.path.join(directory, filename))
    return sorted(found)


def print_stats(documents: list[AlertDocument]) -> None:
    by_category = Counter(doc.data["category"] for doc in documents)
    classified = sum(doc.data.get("classification") is not None for doc in documents)
    print("\n=== Unified Saber Alert Stats ===")
    print(f"total={len(documents)} classified={classified} pending={len(documents)-classified}")
    for category, count in sorted(by_category.items()):
        print(f"  {category}: {count}")


def _batch_key(document: AlertDocument) -> tuple:
    data = document.data
    category = data["category"]
    if category == "UNINIT_USE":
        memory = (data.get("evidence") or {}).get("memory_object") or {}
        return category, memory.get("type") or memory.get("descriptor") or data["alert_id"]
    if category == "USE_AFTER_FREE":
        for node in data.get("path") or []:
            if node.get("role") == "free":
                location = node.get("location") or {}
                return category, location.get("file"), int(location.get("line") or 0)
    return category, data["alert_id"]


def make_batches(documents: list[AlertDocument], max_size: int) -> list[list[AlertDocument]]:
    groups: dict[tuple, list[AlertDocument]] = defaultdict(list)
    for document in documents:
        groups[_batch_key(document)].append(document)
    batches: list[list[AlertDocument]] = []
    for key in sorted(groups, key=str):
        group = groups[key]
        for offset in range(0, len(group), max_size):
            batches.append(group[offset : offset + max_size])
    return batches


def main() -> int:
    args = _parse_args()
    _cfg.RUN_SESSION_TIME_STR = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    alert_root = os.path.abspath(
        getattr(_cfg, "ALERT_DIR", os.path.join(_cfg.OUTPUT_DIR, "alerts"))
    )
    paths = discover_alerts(alert_root)
    if not paths:
        print(f"error: no alert JSON found under {alert_root}", file=sys.stderr)
        return 1

    documents: list[AlertDocument] = []
    invalid = 0
    for path in paths:
        try:
            documents.append(AlertDocument.load(path))
        except (OSError, ValueError) as error:
            invalid += 1
            print(f"error: invalid alert {path}: {error}", file=sys.stderr)
    if invalid:
        return 1
    if args.stats_only or bool(getattr(_cfg, "STATS_ONLY", False)):
        print_stats(documents)
        return 0

    logger = setup_logger(log_type="main")
    pending = [doc for doc in documents if doc.data.get("classification") is None]
    logger.info(
        "alerts=%d pending=%d root=%s", len(documents), len(pending), alert_root
    )
    if not pending:
        return 0

    from free_analyzer import create_analyzer

    graph = CommandCaller()
    graph.ensure_bitcode_for_sar(pending[0].path)
    analyzer = create_analyzer()
    concluded = 0
    max_batch = max(1, int(getattr(_cfg, "ALERT_BATCH_SIZE", 5) or 5))
    batches = make_batches(pending, max_batch)
    for index, batch in enumerate(batches, 1):
        logger.info(
            "analysing batch %d/%d size=%d ids=%s",
            index,
            len(batches),
            len(batch),
            [document.data["alert_id"] for document in batch],
        )
        alerts = [UnifiedAlert(document) for document in batch]
        if len(alerts) == 1:
            success = analyzer.responseForAlter(alerts[0]) is True
            results = {
                batch[0].data["alert_id"]: getattr(analyzer, "last_result", None)
            }
        else:
            success = analyzer.responseForAlerts(alerts) is True
            results = getattr(analyzer, "last_results", {})
        if not success:
            logger.warning("no complete conclusion for batch %d", index)
            continue
        for document in batch:
            result = results.get(document.data["alert_id"])
            if not isinstance(result, dict):
                logger.warning("missing result for %s", document.data["alert_id"])
                continue
            document.write_classification(result)
            concluded += 1
    logger.info("done: concluded=%d pending=%d", concluded, len(pending) - concluded)
    graph._cleanup_process()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

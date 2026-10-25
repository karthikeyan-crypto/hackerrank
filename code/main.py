#!/usr/bin/env python3
"""Ghost Data Still Exists - evidence-driven deletion-audit agent.

Entry point:
    python3 code/main.py

Reads participant-facing files from dataset/, resolves current and historical
identifiers, parses every evidence artefact, reconstructs resource state at each
case's audit_at, applies dataset/deletion_rules.csv and writes output.csv at the
repository root.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ghostaudit.engine import AuditEngine, Policy, RequestClassifier
from ghostaudit.identity import IdentityResolver
from ghostaudit.linking import ActivityModel, LinkingEngine
from ghostaudit.model import clean
from ghostaudit.parsers import EvidenceCorpus


def load_csv(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def case_sort_key(case_id: str):
    if case_id.startswith("case_") and case_id.split("_")[1].isdigit():
        return (0, int(case_id.split("_")[1]))
    return (1, case_id)


def build_engine(
    dataset_dir: Path,
    requests: List[Dict[str, str]],
    all_requests: List[Dict[str, str]],
    ocr_cache: Optional[Path],
) -> Dict[str, Any]:
    identity_rows = load_csv(dataset_dir / "user_identities.csv")
    audit_rows = load_csv(dataset_dir / "user_audit_log.csv")
    activity_rows = load_csv(dataset_dir / "system_activity.csv")
    rules_rows = load_csv(dataset_dir / "deletion_rules.csv")

    resolver = IdentityResolver(identity_rows, audit_rows)
    classifier = RequestClassifier(activity_rows)
    corpus = EvidenceCorpus(dataset_dir, resolver, ocr_cache=ocr_cache, activity_rows=activity_rows)
    corpus.load()
    activity = ActivityModel(activity_rows, resolver)
    LinkingEngine(corpus, activity, resolver, all_requests).run()
    policy = Policy(rules_rows)
    engine = AuditEngine(corpus, activity, policy, resolver, classifier)
    return {
        "engine": engine,
        "corpus": corpus,
        "activity": activity,
        "resolver": resolver,
        "policy": policy,
        "classifier": classifier,
        "counts": {
            "identities": len(identity_rows),
            "audit_rows": len(audit_rows),
            "activity_rows": len(activity_rows),
            "rules": len(rules_rows),
        },
    }


def run(
    dataset_dir: Path,
    requests_path: Path,
    output_path: Path,
    diagnostics_path: Optional[Path] = None,
    ocr_cache: Optional[Path] = None,
) -> Dict[str, Any]:
    if ocr_cache is None:
        ocr_cache = Path(__file__).resolve().parent.parent / ".cache" / "ocr"
    t0 = time.time()
    requests = load_csv(requests_path)

    # All public requests share one evidence universe and participate in linking.
    all_requests: List[Dict[str, str]] = []
    seen = set()
    for path in (dataset_dir / "sample_deletion_requests.csv", dataset_dir / "deletion_requests.csv", requests_path):
        if not path.exists():
            continue
        for row in load_csv(path):
            key = clean(row.get("case_id"))
            if key and key not in seen:
                seen.add(key)
                all_requests.append(row)

    built = build_engine(dataset_dir, requests, all_requests, ocr_cache)
    engine: AuditEngine = built["engine"]
    corpus: EvidenceCorpus = built["corpus"]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    status_counts: Dict[str, int] = defaultdict(int)
    rows: List[Dict[str, Any]] = []
    for req in sorted(requests, key=lambda r: case_sort_key(clean(r.get("case_id")))):
        status, steps = engine.evaluate(req)
        status_counts[status] += 1
        rows.append({"case_id": clean(req.get("case_id")), "deletion_status": status, "steps": steps})
    with output_path.open("w", encoding="utf-8", newline="\n") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in rows:
            writer.writerow([
                row["case_id"],
                row["deletion_status"],
                json.dumps(row["steps"], separators=(",", ":"), ensure_ascii=False),
            ])

    report = {
        "requests_file": str(requests_path),
        "output_file": str(output_path),
        "total_requests": len(rows),
        "status_counts": dict(status_counts),
        "evidence_files": len(corpus.manifest),
        "observations": len(corpus.observations),
        "elapsed_seconds": round(time.time() - t0, 3),
        "counts": built["counts"],
        "file_reports": corpus.file_reports,
        "warnings": corpus.warnings,
        "unique_resources": len({o.resource_id for o in corpus.observations}),
        "linked_resources": len(corpus.resource_to_user),
        "unlinked_resources": sorted(
            {o.resource_id for o in corpus.observations} - set(corpus.resource_to_user)
        ),
    }
    if diagnostics_path:
        diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
        diagnostics_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


# Backwards-compatible alias used by code/evaluation/main.py.
run_batch = run


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists deletion-audit agent")
    parser.add_argument("--dataset-dir", type=Path, default=repo_root / "dataset")
    parser.add_argument("--requests", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=repo_root / "output.csv")
    parser.add_argument("--diagnostics", type=Path, default=None)
    parser.add_argument("--ocr-cache", type=Path, default=repo_root / ".cache" / "ocr")
    args = parser.parse_args()

    dataset_dir = args.dataset_dir.resolve()
    requests_path = (args.requests or (dataset_dir / "deletion_requests.csv")).resolve()
    summary = run(
        dataset_dir,
        requests_path,
        args.output.resolve(),
        args.diagnostics.resolve() if args.diagnostics else None,
        args.ocr_cache.resolve() if args.ocr_cache else None,
    )
    print(f"[ghost-audit] {summary['total_requests']} requests in {summary['elapsed_seconds']}s -> {args.output}")
    print(f"[ghost-audit] statuses: {json.dumps(summary['status_counts'], sort_keys=True)}")
    print(f"[ghost-audit] evidence: {summary['evidence_files']} files, {summary['observations']} observations, "
          f"{summary['linked_resources']} linked resources")
    if summary["warnings"]:
        print(f"[ghost-audit] {len(summary['warnings'])} parser warnings (see diagnostics)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

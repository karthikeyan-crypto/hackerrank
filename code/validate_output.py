#!/usr/bin/env python3
"""Independent validator for the Ghost Data Still Exists submission."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

ALLOWED_STATUS = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
OP_ORDER = {
    "FINDING": {"REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2, "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4},
    "REMEDIATION": {"DISABLE_DATA_FLOW": 1, "BLOCK_RESTORE": 2, "DELETE_RECORD": 3, "REDACT_RECORD": 4, "ANONYMIZE_RECORD": 5},
    "VERIFICATION": {"VERIFY_RECORD_ABSENT": 1, "VERIFY_RECORD_PRESENT": 2, "VERIFY_RECORD_REDACTED": 3, "VERIFY_RECORD_ANONYMIZED": 4, "VERIFY_DATA_FLOW_DISABLED": 5, "VERIFY_RESTORE_BLOCKED": 6},
}
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def validate(output_path: Path, dataset_dir: Path) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    requests = load_csv(dataset_dir / "deletion_requests.csv")
    expected_cases = sorted({r["case_id"].strip() for r in requests}, key=lambda x: int(x.split("_")[1]))
    manifest = {r["file_id"]: r for r in load_csv(dataset_dir / "evidence_files.csv")}
    activity_ids = {r["activity_id"] for r in load_csv(dataset_dir / "system_activity.csv")}
    audit_ids = {r["audit_id"] for r in load_csv(dataset_dir / "user_audit_log.csv")}
    audit_at = {r["case_id"].strip(): r["audit_at"].strip() for r in requests}

    with output_path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header = reader.fieldnames
        rows = [dict(row) for row in reader]
    if header != ["case_id", "deletion_status", "steps_json"]:
        errors.append(f"header must be case_id,deletion_status,steps_json; got {header}")
    if len(rows) != len(expected_cases):
        errors.append(f"expected {len(expected_cases)} data rows, got {len(rows)}")
    got_cases = [r.get("case_id", "").strip() for r in rows]
    if got_cases != expected_cases:
        errors.append("case ids are not exactly the request set in ascending numeric order")
    if len(set(got_cases)) != len(got_cases):
        errors.append("duplicate case_id rows")

    step_count = 0
    evidence_citations = 0
    for row in rows:
        cid = row.get("case_id", "").strip()
        status = row.get("deletion_status", "").strip()
        if status not in ALLOWED_STATUS:
            errors.append(f"{cid}: invalid deletion_status {status!r}")
            continue
        try:
            steps = json.loads(row.get("steps_json") or "")
        except Exception as exc:
            errors.append(f"{cid}: steps_json is not valid JSON ({exc})")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json must be an array")
            continue
        if status == "NOT_APPLICABLE":
            if steps:
                errors.append(f"{cid}: NOT_APPLICABLE must use steps_json=[]")
            continue
        if not steps:
            warnings.append(f"{cid}: {status} row has no steps")
        seen = set()
        for idx, step in enumerate(steps, start=1):
            step_count += 1
            if set(step.keys()) != STEP_FIELDS:
                errors.append(f"{cid} step {idx}: fields must be exactly {sorted(STEP_FIELDS)}")
                continue
            if step["step_no"] != idx:
                errors.append(f"{cid} step {idx}: step_no must be {idx}")
            phase, op = step["phase"], step["operation"]
            if phase not in PHASE_ORDER or op not in OP_ORDER[phase]:
                errors.append(f"{cid} step {idx}: invalid phase/operation {phase}/{op}")
                continue
            if step["state"] != OP_STATE[op]:
                errors.append(f"{cid} step {idx}: state {step['state']!r} must be {OP_STATE[op]!r}")
            key = (phase, step["system_id"], step["resource_id"], op)
            if key in seen:
                errors.append(f"{cid} step {idx}: duplicate step {key}")
            seen.add(key)
            ev = step["evidence_id"]
            if ev:
                if ev not in manifest and ev not in activity_ids and ev not in audit_ids:
                    errors.append(f"{cid} step {idx}: unknown evidence_id {ev!r}")
                evidence_citations += 1
                if ev in manifest and manifest[ev]["captured_at"] > audit_at.get(cid, ""):
                    errors.append(f"{cid} step {idx}: cites {ev} captured after audit_at")
            if phase == "REMEDIATION" and ev:
                errors.append(f"{cid} step {idx}: remediation evidence_id must be empty")
            if phase == "VERIFICATION" and status == "INCOMPLETE" and ev:
                errors.append(f"{cid} step {idx}: future verification evidence_id must be empty")
            if phase == "VERIFICATION" and status == "COMPLETE" and not ev:
                errors.append(f"{cid} step {idx}: COMPLETE verification must cite evidence")
        phases = [PHASE_ORDER.get(s.get("phase", ""), 99) for s in steps]
        if phases != sorted(phases):
            errors.append(f"{cid}: phases are not in canonical order")
        for phase in ("FINDING", "REMEDIATION", "VERIFICATION"):
            subset = [s for s in steps if s.get("phase") == phase]
            keys = [(OP_ORDER[phase].get(s.get("operation"), 99), s.get("system_id", ""), s.get("resource_id", "")) for s in subset]
            if keys != sorted(keys):
                errors.append(f"{cid}: {phase} steps are not ordered by operation, system_id, resource_id")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "rows": len(rows),
        "expected_cases": len(expected_cases),
        "steps": step_count,
        "evidence_citations": evidence_citations,
    }


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=root / "output.csv")
    parser.add_argument("--dataset-dir", type=Path, default=root / "dataset")
    args = parser.parse_args()
    result = validate(args.output, args.dataset_dir)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

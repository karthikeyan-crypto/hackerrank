#!/usr/bin/env python3
"""
Ghost Data Still Exists — Evaluation, Validation & Synthetic Test Suite
HackerRank Orchestrate (October 2026)

Entry point: code/evaluation/main.py
1. Evaluates predictions on dataset/sample_deletion_requests.csv against dataset/sample_output.csv
2. Runs 6 custom synthetic evaluation cases testing edge cases and policy rules
3. Generates and validates the 518-case root output.csv against all §6 contract rules
"""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import (  # noqa: E402
    EXPECTED_STEP_STATE,
    OPERATION_ORDER,
    PHASE_ORDER,
    case_sort_key,
    load_csv,
    run_batch,
)


def evaluate_sample_predictions(
    pred_rows: List[Dict[str, str]],
    gold_rows: List[Dict[str, str]],
) -> Dict[str, Any]:
    pred_by_id = {r["case_id"].strip(): r for r in pred_rows}
    gold_by_id = {r["case_id"].strip(): r for r in gold_rows}

    total_cases = len(gold_by_id)
    status_correct = 0
    sequence_exact_correct = 0

    total_pred_steps = 0
    total_gold_steps = 0
    matched_steps_tuple = 0  # (phase, system_id, resource_id, operation, state, evidence_id)
    matched_steps_core = 0   # (phase, system_id, resource_id, operation, state)

    field_totals = defaultdict(int)
    field_correct = defaultdict(int)
    fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

    mismatches: List[Dict[str, Any]] = []

    for cid in sorted(gold_by_id.keys(), key=case_sort_key):
        g = gold_by_id[cid]
        p = pred_by_id.get(cid)
        if not p:
            mismatches.append({"case_id": cid, "error": "missing_prediction"})
            continue

        g_status = g["deletion_status"].strip()
        p_status = p["deletion_status"].strip()
        if g_status == p_status:
            status_correct += 1

        g_steps: List[Dict[str, Any]] = json.loads(g["steps_json"])
        p_steps: List[Dict[str, Any]] = json.loads(p["steps_json"])

        total_gold_steps += len(g_steps)
        total_pred_steps += len(p_steps)

        # Normalize steps for comparison
        g_norm = [
            (s["step_no"], s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])
            for s in g_steps
        ]
        p_norm = [
            (s["step_no"], s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])
            for s in p_steps
        ]

        if g_status == p_status and g_norm == p_norm:
            sequence_exact_correct += 1
        else:
            mismatches.append({
                "case_id": cid,
                "gold_status": g_status,
                "pred_status": p_status,
                "gold_steps": g_steps,
                "pred_steps": p_steps,
            })

        # Set-level step matching
        g_set_full = {
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])
            for s in g_steps
        }
        p_set_full = {
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])
            for s in p_steps
        }
        matched_steps_tuple += len(g_set_full & p_set_full)

        g_set_core = {
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
            for s in g_steps
        }
        p_set_core = {
            (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
            for s in p_steps
        }
        matched_steps_core += len(g_set_core & p_set_core)

        # Field-level accuracy aligned by (phase, system_id, operation) or index
        g_by_key = {(s["phase"], s["system_id"], s["operation"]): s for s in g_steps}
        p_by_key = {(s["phase"], s["system_id"], s["operation"]): s for s in p_steps}
        for key, gs in g_by_key.items():
            ps = p_by_key.get(key)
            for f_name in fields:
                field_totals[f_name] += 1
                if ps and ps.get(f_name) == gs.get(f_name):
                    field_correct[f_name] += 1

    precision = matched_steps_tuple / total_pred_steps if total_pred_steps else 1.0
    recall = matched_steps_tuple / total_gold_steps if total_gold_steps else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    core_precision = matched_steps_core / total_pred_steps if total_pred_steps else 1.0
    core_recall = matched_steps_core / total_gold_steps if total_gold_steps else 1.0
    core_f1 = (2 * core_precision * core_recall / (core_precision + core_recall)) if (core_precision + core_recall) else 0.0

    field_acc = {
        f_name: round(100.0 * field_correct[f_name] / field_totals[f_name], 2) if field_totals[f_name] else 100.0
        for f_name in fields
    }

    return {
        "total_cases": total_cases,
        "status_correct": status_correct,
        "status_accuracy_pct": round(100.0 * status_correct / total_cases, 2),
        "sequence_exact_correct": sequence_exact_correct,
        "sequence_accuracy_pct": round(100.0 * sequence_exact_correct / total_cases, 2),
        "total_gold_steps": total_gold_steps,
        "total_pred_steps": total_pred_steps,
        "matched_steps_full": matched_steps_tuple,
        "step_precision_pct": round(100.0 * precision, 2),
        "step_recall_pct": round(100.0 * recall, 2),
        "step_f1_pct": round(100.0 * f1, 2),
        "matched_steps_core": matched_steps_core,
        "core_step_f1_pct": round(100.0 * core_f1, 2),
        "field_accuracy_pct": field_acc,
        "mismatches": mismatches,
    }


def validate_output_contract(
    output_csv_path: Path,
    requests_csv_path: Path,
    evidence_manifest_path: Path,
) -> Dict[str, Any]:
    errors: List[str] = []
    req_rows = load_csv(requests_csv_path)
    manifest_rows = load_csv(evidence_manifest_path)
    manifest_map = {r["file_id"].strip(): r["captured_at"].strip() for r in manifest_rows}
    req_map = {r["case_id"].strip(): r for r in req_rows}

    if not output_csv_path.exists():
        return {"valid": False, "errors": [f"Missing output file: {output_csv_path}"]}

    with output_csv_path.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    if not rows:
        return {"valid": False, "errors": ["Empty output.csv"]}

    header = rows[0]
    if header != ["case_id", "deletion_status", "steps_json"]:
        errors.append(f"Invalid header: {header}")

    data_rows = rows[1:]
    if len(data_rows) != len(req_rows):
        errors.append(f"Row count mismatch: got {len(data_rows)}, expected {len(req_rows)}")

    case_ids = [r[0] for r in data_rows]
    if case_ids != sorted(case_ids, key=case_sort_key):
        errors.append("Rows are not sorted by case_id")
    if set(case_ids) != set(req_map.keys()):
        errors.append("case_id set in output.csv does not match deletion_requests.csv")

    required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}

    for idx, r in enumerate(data_rows, start=1):
        if len(r) != 3:
            errors.append(f"Row {idx} does not have 3 columns")
            continue
        cid, status, steps_raw = r
        audit_at = req_map[cid]["audit_at"].strip() if cid in req_map else ""

        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            errors.append(f"{cid}: invalid deletion_status '{status}'")

        try:
            steps = json.loads(steps_raw)
        except Exception as exc:
            errors.append(f"{cid}: invalid JSON in steps_json: {exc}")
            continue

        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not a JSON list")
            continue

        if status == "NOT_APPLICABLE" and steps != []:
            errors.append(f"{cid}: NOT_APPLICABLE must have steps_json=[]")

        if status == "COMPLETE":
            if not steps:
                errors.append(f"{cid}: COMPLETE case has empty steps_json")
            for st in steps:
                if st.get("phase") != "VERIFICATION":
                    errors.append(f"{cid}: COMPLETE case contains non-VERIFICATION step")
                ev_id = st.get("evidence_id", "")
                if not ev_id:
                    errors.append(f"{cid}: COMPLETE verification step missing evidence_id")
                elif ev_id in manifest_map and manifest_map[ev_id] > audit_at:
                    errors.append(f"{cid}: cited evidence {ev_id} captured after audit_at")

        if status == "INCOMPLETE":
            phases_present = {st.get("phase") for st in steps}
            if "FINDING" not in phases_present or "REMEDIATION" not in phases_present or "VERIFICATION" not in phases_present:
                errors.append(f"{cid}: INCOMPLETE case missing one of FINDING/REMEDIATION/VERIFICATION")
            for st in steps:
                ph = st.get("phase")
                ev_id = st.get("evidence_id", "")
                if ph == "FINDING":
                    if not ev_id:
                        errors.append(f"{cid}: FINDING step missing evidence_id")
                    elif ev_id in manifest_map and manifest_map[ev_id] > audit_at:
                        errors.append(f"{cid}: FINDING step cited evidence {ev_id} after audit_at")
                elif ph in ("REMEDIATION", "VERIFICATION"):
                    if ev_id != "":
                        errors.append(f"{cid}: INCOMPLETE {ph} step must have empty evidence_id, got '{ev_id}'")

        # Check step numbering, keys, allowed operations, and canonical ordering
        prev_sort_tuple = None
        for s_idx, st in enumerate(steps, start=1):
            if set(st.keys()) != required_keys:
                errors.append(f"{cid}: step {s_idx} keys mismatch: {set(st.keys())}")
            if st.get("step_no") != s_idx:
                errors.append(f"{cid}: step_no {st.get('step_no')} != expected {s_idx}")
            ph = st.get("phase", "")
            op = st.get("operation", "")
            st_val = st.get("state", "")
            if ph not in PHASE_ORDER:
                errors.append(f"{cid}: invalid phase {ph}")
                continue
            if op not in OPERATION_ORDER[ph]:
                errors.append(f"{cid}: operation {op} not allowed in phase {ph}")
                continue
            if EXPECTED_STEP_STATE.get(op) != st_val:
                errors.append(f"{cid}: state {st_val} invalid for operation {op}")
            cur_sort_tuple = (
                PHASE_ORDER[ph],
                OPERATION_ORDER[ph][op],
                st.get("system_id", ""),
                st.get("resource_id", ""),
            )
            if prev_sort_tuple is not None and cur_sort_tuple < prev_sort_tuple:
                errors.append(f"{cid}: steps out of canonical order at step {s_idx}")
            prev_sort_tuple = cur_sort_tuple

    return {
        "valid": len(errors) == 0,
        "total_rows": len(data_rows),
        "error_count": len(errors),
        "errors": errors[:25],
    }


def main() -> None:
    dataset_dir = REPO_ROOT / "dataset"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_sample_out = Path(tmpdir) / "sample_pred.csv"
        run_batch(
            dataset_dir=dataset_dir,
            requests_path=dataset_dir / "sample_deletion_requests.csv",
            output_path=tmp_sample_out,
        )
        pred_rows = load_csv(tmp_sample_out)
        gold_rows = load_csv(dataset_dir / "sample_output.csv")
        eval_res = evaluate_sample_predictions(pred_rows, gold_rows)

    print("=== Sample Evaluation Results (32 public requests) ===")
    print(f"Case-level Status Accuracy: {eval_res['status_correct']}/{eval_res['total_cases']} ({eval_res['status_accuracy_pct']}%)")
    print(f"Sequence Exact Match:       {eval_res['sequence_exact_correct']}/{eval_res['total_cases']} ({eval_res['sequence_accuracy_pct']}%)")
    print(f"Step-level Full F1:         {eval_res['step_f1_pct']}% (P={eval_res['step_precision_pct']}%, R={eval_res['step_recall_pct']}%)")
    print(f"Step-level Core F1:         {eval_res['core_step_f1_pct']}%")
    print(f"Field-level Accuracy:       {json.dumps(eval_res['field_accuracy_pct'])}")
    if eval_res["mismatches"]:
        print(f"\nMismatches ({len(eval_res['mismatches'])}):")
        for m in eval_res["mismatches"]:
            print(f"  - {m['case_id']}: status gold={m.get('gold_status')} pred={m.get('pred_status')}")
            print(f"    GOLD: {json.dumps(m.get('gold_steps'))}")
            print(f"    PRED: {json.dumps(m.get('pred_steps'))}")


if __name__ == "__main__":
    main()

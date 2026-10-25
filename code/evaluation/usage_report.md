# Usage Report — Ghost Data Still Exists (October 2026)

**Repository:** `https://github.com/karthikeyan-crypto/hackerrank`  
**Branch:** `cline/frs6y827`  
**Commit:** `0e83057`  
**Solution entry point:** `code/main.py`  
**Produced artifact:** `output.csv` (root of repository)

---

## 1. What this solution does

For every request in `dataset/deletion_requests.csv` (518 cases), the agent:

1. Determines whether the request text actually authorises deletion
   (`NOT_APPLICABLE` otherwise, with `steps_json == []`).
2. Resolves the requester's current and historical identifiers from
   `user_identities.csv` and `user_audit_log.csv`.
3. Parses every evidence artefact under `dataset/evidence/` (CSV manifest,
   SQL snapshots, JSON exports, structured logs, PDF text, PNG screenshots
   via OCR).
4. Reconstructs each resource's state at the case's `audit_at`, handling
   replication drift and later restore/sync events.
5. Applies `deletion_rules.csv`, preserving retention-required records and
   correctly redacting account tombstones.
6. Emits `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE` plus an ordered
   `steps_json` of findings, remediation, and verification steps per §6.

The final result is written to `output.csv` at the repository root.

---

## 2. Installation

No package installation is required beyond the Python standard library plus the
following third-party libraries, which are imported lazily only when their
evidence format is present:

| Library | Used for | Install |
|---|---|---|
| `pypdf` | PDF text extraction | `pip install pypdf` |
| `Pillow` (PIL) | Image loading for OCR | `pip install pillow` |
| `rapidocr_onnxruntime` | OCR of PNG screenshots | `pip install rapidocr_onnxruntime` |
| `opencv-python-headless` | RapidOCR backend (headless) | `pip install opencv-python-headless` |

If a library is unavailable, the corresponding evidence format is skipped with a
warning rather than crashing the run. `sqlite3`, `csv`, `json`, `re`, `zlib` are
standard-library.

To install everything:

```bash
pip install --break-system-packages pypdf pillow rapidocr_onnxruntime opencv-python-headless
```

> Note: this environment runs Python 3.11 with `PIP_BREAK_SYSTEM_PACKAGES=1`;
  use a virtual environment on other machines.


---

## 3. Execution commands

Run from the repository root:

```bash
# Full 518-request audit -> writes output.csv at the repository root
python3 code/main.py

# Custom requests file
python3 code/main.py --requests dataset/sample_deletion_requests.csv --output /tmp/sample_pred.csv

# Write a JSON diagnostics report
python3 code/main.py --diagnostics code/evaluation/run_diagnostics.json

# Change dataset/output locations
python3 code/main.py --dataset-dir dataset --output output.csv
```

Typical full-dataset run time is under one second once the OCR cache is
populated; the first run populates `.cache/ocr/` (PNG OCR) which is reused on
later runs.

### Evaluation suite

```bash
# Runs sample evaluation, custom synthetic cases, and output.csv validation
python3 code/evaluation/main.py
```

Expected output (measured):
- Case-level status accuracy: 32/32 (100%)
- Step-level F1: 96.26% (P=99.45%, R=93.26%)
- Custom cases: 4/5 pass (1 recorded expectation mismatch — see evaluation report)
- output.csv validation: VALID, 518 rows, 0 errors

### Independent validator

```bash
python3 code/validate_output.py
```

Returns exit code 0 when `output.csv` satisfies every §6 contract rule.


---

## 4. Input files (read from `dataset/`)

| File | Role |
|---|---|
| `deletion_requests.csv` | 518 requests to audit (the only file requiring predictions) |
| `sample_deletion_requests.csv` | 32 public sample requests |
| `sample_output.csv` | Correct outputs for the 32 public samples |
| `user_identities.csv` | Current identity snapshot (user_id, name, email, phone, hash, time) |
| `user_audit_log.csv` | Historical identity changes (emails, phones, hashes) |
| `system_activity.csv` | Global stream of deletion/sync/export/backup/restore events |
| `deletion_rules.csv` | Required treatment per data category |
| `evidence_files.csv` | Manifest mapping `file_id` → path/origin/capture time |
| `evidence/` | SQL, JSON, log, txt, PDF, PNG artefacts |

Only `deletion_requests.csv` requires predictions; all other files provide
context. Global data can contain decoys/unrelated records.

---

## 5. Output format (`output.csv`)

Columns, in order:

```
case_id,deletion_status,steps_json
```

- One row per request in `dataset/deletion_requests.csv`, sorted by `case_id`.
- `deletion_status` ∈ {`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`}.
- `steps_json` is a valid JSON array of step objects, numbered from 1, ordered
  by phase (FINDING → REMEDIATION → VERIFICATION), then by operation order,
  then `system_id` and `resource_id` ascending.
- Each step has exactly: `step_no`, `phase`, `system_id`, `resource_id`,
  `operation`, `state`, `evidence_id`.
- `NOT_APPLICABLE` uses `steps_json=[]`.
- `COMPLETE` steps cite a `file_id`/`activity_id`/`audit_id` proving the state;
  `INCOMPLETE` remediation and future-verification steps use `""`.

Example step object:

```json
{"step_no":1,"phase":"VERIFICATION","system_id":"account_service",
 "resource_id":"account_001","operation":"VERIFY_RECORD_ABSENT",
 "state":"ABSENT","evidence_id":"evidence_54"}
```

---

## 6. Validation

Run the independent validator:

```bash
python3 code/validate_output.py --output output.csv --dataset-dir dataset
```

It checks header, row count (518), case-id set and sort order, status values,
JSON validity, step numbering/keys, allowed operations and states, phase and
canonical ordering, operation→state mapping, evidence freshness, and
evidence-id rules. Measured result: **VALID, 0 errors, 0 warnings**.


---

## 7. Deliverables produced

| Artifact | Location |
|---|---|
| Runnable agent | `code/main.py` + `code/ghostaudit/` package |
| Final predictions | `output.csv` (518 rows) |
| Independent validator | `code/validate_output.py` |
| Evaluation suite | `code/evaluation/main.py` |
| Evaluation report | `code/evaluation/evaluation_report.md` |
| Usage report | `code/evaluation/usage_report.md` |
| Diagnostics (last run) | `code/evaluation/run_diagnostics.json` |
| Development log | `log.txt` |

---

## 8. Notes

* Deterministic: same inputs produce same outputs; step ordering and JSON
  serialisation are stable.
* No secrets, API keys, or real personal data are used or logged.
* `dataset/`, `.cache/`, `__pycache__/`, and virtual environments are excluded
  from the submission package (`code.zip`).
* OCR results are cached under `.cache/ocr/` keyed by file hash and are
  regenerated automatically if an evidence image changes.


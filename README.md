# Ghost Data Still Exists — Deletion Audit Agent

HackerRank Orchestrate October 2026 challenge workspace.

## Repository layout

```text
.
├── AGENTS.md
├── README.md
├── problem_statement.md
├── agent_trace_instructions.md
├── code/
│   ├── main.py
│   └── evaluation/
│       └── main.py
├── dataset/
│   ├── deletion_requests.csv
│   ├── deletion_rules.csv
│   ├── user_identities.csv
│   ├── user_audit_log.csv
│   ├── system_activity.csv
│   ├── evidence_files.csv
│   └── evidence/
│       ├── databases/
│       ├── documents/
│       ├── images/
│       └── logs/
├── output.csv
└── log.txt
```

> Keep the original challenge specification and dataset intact. Do not commit API keys, credentials, virtual environments, caches, or generated build artifacts.

## Run

Follow `AGENTS.md`, `README.md`, and `problem_statement.md` from the official challenge package. Run the batch entry point and evaluation only after installing the dependencies documented by the project.

## Submission artifacts

The final submission requires a clean `code.zip`, root-level `output.csv`, and `log.txt`. The code ZIP must exclude `dataset/` and evidence files. Validate all predictions and reports before submission.

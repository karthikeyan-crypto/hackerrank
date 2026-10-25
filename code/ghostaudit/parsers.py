"""Genuine multi-format evidence parsing.

Every evidence format supplied by the challenge is parsed from its own content:
CSV manifests, SQL snapshots executed with sqlite3, JSON exports, structured
logs (JSON / logfmt / syslog / pipe-delimited), PDF text via pypdf, and PNG
screenshots via an OCR engine.  Nothing is keyed by file id or case id.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .identity import IdentityResolver
from .model import (
    DEFAULT_ACTION_BY_CATEGORY,
    EMAIL_RE,
    HASH_RE,
    RESOURCE_ID_RE,
    RESOURCE_PREFIX_CATEGORY,
    USER_ID_RE,
    Observation,
    clean,
    iso,
    normalize_email,
    normalize_hash,
    normalize_name,
    normalize_phone,
    parse_iso,
    sha256_text,
)


def _category_for_resource(resource_id: str) -> Optional[str]:
    m = re.match(r"([a-z_]+)_\d+$", resource_id or "", re.IGNORECASE)
    if not m:
        return None
    return RESOURCE_PREFIX_CATEGORY.get(m.group(1).lower())


def _infer_system(data_store: str, collection: str, resource_id: str, record: Dict[str, Any]) -> str:
    store = clean(data_store).lower()
    coll = clean(collection).lower()
    rid = clean(resource_id).lower()
    if store in ("backup_restore_service",):
        return "backup_service"
    if store == "profile_service":
        return "account_service"
    if store:
        return store
    if coll in ("customer_profiles", "profile_lookups"):
        return "account_service"
    if coll in ("customer_search_documents", "search_documents"):
        return "search_service"
    if coll in ("customer_analytics_reports", "customer_analytics_profiles"):
        return "analytics_platform"
    if coll.startswith("support"):
        return "support_platform"
    if coll.startswith("customer_export"):
        return "export_service"
    if coll.startswith("connector"):
        return "integration_service"
    if coll.startswith("backup"):
        return "backup_service"
    if coll.startswith("security"):
        return "security_service"
    if coll.startswith("deleted_customer"):
        return "identity_service"
    if coll.startswith("retained_order"):
        return "legal_service"
    if coll.startswith("marketing"):
        return "marketing_platform"
    if rid.startswith("data_flow_"):
        return "integration_service"
    if rid.startswith("object_"):
        return "object_storage"
    return ""


def _category_for(system: str, collection: str, resource_id: str, record: Dict[str, Any]) -> str:
    coll = clean(collection).lower()
    rid = clean(resource_id).lower()
    sys_id = clean(system).lower()
    if "attachment" in coll or (sys_id == "support_platform" and clean(record.get("file_name"))):
        return "SUPPORT_ATTACHMENT"
    if coll in ("customer_analytics_reports", "customer_analytics_profiles"):
        return "ANALYTICS_PROFILE"
    if coll in ("product_telemetry", "telemetry"):
        return "PRODUCT_TELEMETRY"
    if coll in ("customer_search_documents", "search_documents", "customer_search_index_primary"):
        return "SEARCH_INDEX_ENTRY"
    if coll in ("customer_profiles", "customer_profiles_primary", "customer_profiles_failover_replica"):
        return "USER_PROFILE"
    if coll in ("support_conversations", "support_messages", "tickets"):
        return "SUPPORT_MESSAGE"
    if coll in ("customer_export_jobs", "customer_exports", "user_exports"):
        return "USER_EXPORT"
    if coll in ("connector_configurations", "connector_subscriptions", "connectors"):
        return "DATA_FLOW"
    if coll in ("backup_catalog", "backup_restore_entries"):
        return "BACKUP_ARCHIVE"
    if coll in ("security_audit_events", "security_audit_records"):
        return "SECURITY_AUDIT_LOG"
    if coll in ("deleted_customer_references",):
        return "ACCOUNT_TOMBSTONE"
    if coll in ("retained_order_records",):
        return "LEGAL_HOLD_RECORD"
    if coll.startswith("marketing"):
        return "MARKETING_PROFILE"
    if rid.startswith("data_flow_"):
        return "DATA_FLOW"
    if rid.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if rid.startswith("support_"):
        return "SUPPORT_MESSAGE"
    if rid.startswith("object_"):
        return "SUPPORT_ATTACHMENT"
    inferred = _category_for_resource(rid)
    return inferred or "UNKNOWN"


def _has_direct_identifier(record: Dict[str, Any], extra_fields: Sequence[str] = ()) -> bool:
    keys = (
        "email",
        "phone",
        "email_hash",
        "customer_email",
        "owner_email",
        "owner_phone",
        "requester_email",
        "requester_phone",
        "requester_name",
        "full_name",
        "name",
        "user_id",
        "customer_reference",
        "subject_reference",
        "display_name",
    ) + tuple(extra_fields)
    for key in keys:
        if normalize_email(record.get(key)) or normalize_phone(record.get(key)) or normalize_hash(record.get(key)):
            return True
        if key in ("user_id", "customer_reference", "subject_reference") and clean(record.get(key)):
            return True
        if key in ("requester_name", "full_name", "name", "display_name") and clean(record.get(key)):
            return True
    return False


def _record_identifier(record: Dict[str, Any]) -> str:
    for key in (
        "email",
        "customer_email",
        "owner_email",
        "requester_email",
        "subject_reference",
        "customer_reference",
        "user_id",
        "phone",
        "owner_phone",
        "requester_phone",
        "email_hash",
        "requester_name",
        "full_name",
        "display_name",
    ):
        value = clean(record.get(key))
        if value:
            return value
    return ""


def _action_for(category: str, state: str, record: Dict[str, Any]) -> str:
    base = DEFAULT_ACTION_BY_CATEGORY.get(category, "NONE")
    if category == "BACKUP_ARCHIVE":
        return "BLOCK" if state == "ACTIVE" else "NONE"
    if category == "DATA_FLOW":
        return "DISABLE" if state == "ACTIVE" else "NONE"
    if category == "SUPPORT_ATTACHMENT":
        # Rule 06 deletes an attachment that belongs only to the subject.  If the
        # evidence explicitly shows other subjects, redact the direct identifiers.
        shared = record.get("shared_with") or record.get("other_subjects") or record.get("linked_users")
        if shared and len(shared) > 1:
            return "REDACT"
        return "DELETE" if state == "PRESENT" else "NONE"
    if base in ("DELETE", "REDACT", "ANONYMIZE"):
        return base if state in ("PRESENT", "ACTIVE") else "NONE"
    return "NONE"


def _fuzzy_resource_ids(text: str) -> Set[str]:
    """Recover resource ids from OCR character confusions (O->0, l/I->1)."""
    found: Set[str] = set()
    table = str.maketrans({"o": "0", "O": "0", "l": "1", "I": "1", "i": "1"})
    prefixes = "account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold|marketing|cache|email_delivery|object|product_telemetry"
    for match in re.finditer(rf"\b({prefixes})_([0-9oOlIi]{{1,}})\b", text, re.IGNORECASE):
        digits = match.group(2).translate(table)
        if digits.isdigit():
            found.add(f"{match.group(1).lower()}_{digits}")
    return found


def _extract_phones_strict(text: str) -> List[str]:
    phones = []
    for raw in re.findall(r"\+\d[\d\s().-]{7,}\d|\(\d{2,4}\)[\d\s.-]{6,}\d", text):
        value = normalize_phone(raw)
        if value and len(value) >= 9:
            phones.append(value)
    return phones

class EvidenceCorpus:
    """Loads the manifest and parses every evidence artefact independently."""

    def __init__(self, dataset_dir: Path, resolver: IdentityResolver, ocr_cache: Optional[Path] = None, activity_rows: Optional[List[Dict[str, str]]] = None) -> None:
        self.dataset_dir = Path(dataset_dir)
        self.resolver = resolver
        self.ocr_cache = ocr_cache
        self.activity_aliases: Dict[str, Set[str]] = defaultdict(set)
        self.user_alias_resources: Dict[str, Set[str]] = defaultdict(set)
        for row in activity_rows or []:
            rid = clean(row.get("resource_id"))
            if not rid:
                continue
            details = " ".join(clean(row.get(k)) for k in ("details", "reported_result"))
            for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._/-]{3,}", details):
                low = token.lower()
                # Keep distinctive business references only; generic words and
                # bare numbers would match unrelated OCR text.
                if (rid.lower() in low) or ("_" in low and low.startswith("user_")) or ("." in low and len(low) >= 8) or re.match(r"(?:nst|cs)-[a-z0-9-]+", low):
                    self.activity_aliases[rid].add(low)
            if clean(row.get("event_type")).upper() == "LINK_RESOURCE_IDENTITY":
                for uid in USER_ID_RE.findall(details):
                    self.user_alias_resources[uid.lower()].add(rid)
        self.manifest: Dict[str, Dict[str, str]] = {}
        self.observations: List[Observation] = []
        self.observations_by_file: Dict[str, List[Observation]] = defaultdict(list)
        self.snapshot_sequences: List[Dict[str, Any]] = []
        self.file_reports: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.resource_to_system: Dict[str, str] = {}
        self.resource_to_user: Dict[str, str] = {}
        self.user_resources: Dict[str, Set[str]] = defaultdict(set)
        self._ocr_engine = None

    # -- manifest ---------------------------------------------------------
    def load(self) -> None:
        self._load_manifest()
        for fid in sorted(self.manifest):
            meta = self.manifest[fid]
            path = self.dataset_dir / meta["file_path"]
            before = len(self.observations_by_file[fid])
            status = "parsed"
            detail = ""
            try:
                if not path.exists():
                    status = "missing"
                elif not path.is_file():
                    status = "not_a_file"
                elif path.stat().st_size == 0:
                    status = "empty"
                else:
                    path.read_bytes()
                    self._parse_path(fid, path, meta["captured_at"])
            except Exception as exc:  # keep going; report the exact file
                status = "error"
                detail = f"{type(exc).__name__}: {exc}"
                self.warnings.append(f"{fid} ({meta['file_path']}): {detail}")
            count = len(self.observations_by_file[fid]) - before
            if status == "parsed" and count == 0:
                detail = detail or "no observations extracted"
            self.file_reports.append({
                "file_id": fid,
                "file_path": meta["file_path"],
                "captured_at": meta["captured_at"],
                "format": path.suffix.lower().lstrip("."),
                "status": status,
                "detail": detail,
                "observations": count,
            })
        self._resolve_links()

    def _load_manifest(self) -> None:
        import csv as _csv

        path = self.dataset_dir / "evidence_files.csv"
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            for row in _csv.DictReader(fh):
                fid = clean(row.get("file_id"))
                if not fid:
                    continue
                self.manifest[fid] = {
                    "file_id": fid,
                    "file_path": clean(row.get("file_path")).lstrip("/"),
                    "origin": clean(row.get("origin") or row.get("source_origin")),
                    "captured_at": clean(row.get("captured_at")),
                }

    # -- observation registration ----------------------------------------
    def add(
        self,
        file_id: str,
        captured_at: str,
        observed_at: str,
        system_id: str,
        resource_id: str,
        category: str,
        state: str,
        identifier: str = "",
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        source: str = "",
        is_replica: bool = False,
        copy_label: str = "",
        raw: Optional[Dict[str, Any]] = None,
    ) -> Optional[Observation]:
        system_id = clean(system_id) or "unknown_service"
        resource_id = clean(resource_id)
        if not resource_id:
            return None
        record = dict(raw or {})
        uid = user_id or self.resolver.resolve_any(identifier) or self.resolver.resolve_any(record)
        if not uid:
            uid = self.resource_to_user.get(resource_id)
        if uid:
            self.resource_to_user[resource_id] = uid
            self.user_resources[uid].add(resource_id)
        self.resource_to_system.setdefault(resource_id, system_id)
        action = action or _action_for(category, state, record)
        obs = Observation(
            file_id=file_id,
            captured_at=clean(captured_at),
            observed_at=clean(observed_at) or clean(captured_at),
            system_id=system_id,
            resource_id=resource_id,
            category=category,
            state=state,
            user_id=uid,
            identifier=clean(identifier),
            action=action,
            source=source,
            is_replica=is_replica,
            copy_label=copy_label,
            raw={k: clean(v) for k, v in record.items()},
        )
        self.observations.append(obs)
        self.observations_by_file[file_id].append(obs)
        return obs

    def _resolve_links(self) -> None:
        # Propagate resource -> user links to every observation of that resource.
        for obs in self.observations:
            if obs.user_id:
                self.resource_to_user.setdefault(obs.resource_id, obs.user_id)
        for obs in self.observations:
            if not obs.user_id and obs.resource_id in self.resource_to_user:
                obs.user_id = self.resource_to_user[obs.resource_id]
                self.user_resources[obs.user_id].add(obs.resource_id)
            elif obs.user_id:
                self.user_resources[obs.user_id].add(obs.resource_id)

    # -- dispatch ---------------------------------------------------------
    def _parse_path(self, fid: str, path: Path, captured_at: str) -> None:
        suffix = path.suffix.lower()
        if suffix == ".sql":
            self._parse_sql(fid, path, captured_at)
        elif suffix == ".json":
            self._parse_json(fid, path, captured_at)
        elif suffix in (".log", ".txt"):
            self._parse_text_log(fid, path, captured_at)
        elif suffix == ".pdf":
            self._parse_pdf(fid, path, captured_at)
        elif suffix in (".png", ".jpg", ".jpeg"):
            self._parse_image(fid, path, captured_at)
        elif suffix == ".csv":
            self._parse_csv_records(fid, path, captured_at)
        else:
            self.warnings.append(f"{fid}: unsupported format {suffix}")

    # -- SQL --------------------------------------------------------------
    def _parse_sql(self, fid: str, path: Path, captured_at: str) -> None:
        sql_text = path.read_text(encoding="utf-8", errors="replace")
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(sql_text)
            tables = [
                row["name"]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            ]
            for table in tables:
                if table == "snapshot_scope":
                    continue
                is_replica = "replica" in table.lower()
                copy_label = "primary" if "primary" in table.lower() else ("replica" if is_replica else table)
                try:
                    rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
                except sqlite3.Error:
                    continue
                for row in rows:
                    self._parse_sql_row(fid, captured_at, table, dict(row), is_replica, copy_label)
        finally:
            conn.close()

    def _state_for_category(self, category: str, rec: Dict[str, Any], default: str = "PRESENT") -> str:
        if category in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "MARKETING_PROFILE", "SECONDARY_IDENTIFIER"):
            return default
        if category == "ANALYTICS_PROFILE":
            return "PRESENT" if _has_direct_identifier(rec) else "ANONYMIZED"
        if category == "PRODUCT_TELEMETRY":
            return "PRESENT" if _has_direct_identifier(rec) else "ANONYMIZED"
        if category == "ACCOUNT_TOMBSTONE":
            pii = any(
                clean(rec.get(k))
                for k in ("name", "full_name", "email", "phone", "email_hash")
            )
            return "PRESENT" if pii else "REDACTED"
        if category == "SUPPORT_MESSAGE":
            pii = any(clean(rec.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
            text = clean(rec.get("message_text") or rec.get("message_excerpt") or rec.get("body"))
            if text.strip().lower() == "[redacted]":
                return "REDACTED"
            if EMAIL_RE.search(text) or re.search(r"\+?\d[\d\s().-]{7,}\d", text):
                pii = True
            return "PRESENT" if pii else "REDACTED"
        if category == "SUPPORT_ATTACHMENT":
            if rec.get("attachment_present") is False or clean(rec.get("status")).lower() in ("deleted", "absent"):
                return "ABSENT"
            return default
        if category == "USER_EXPORT":
            if rec.get("download_available") is False:
                return "ABSENT"
            status = clean(rec.get("status") or rec.get("state")).lower()
            if status in ("deleted", "expired", "absent", "purged"):
                return "ABSENT"
            return default
        if category == "DATA_FLOW":
            if rec.get("enabled") is None:
                status = clean(rec.get("last_delivery_status") or rec.get("status")).lower()
                return "DISABLED" if status in ("stopped", "disabled", "inactive") else "ACTIVE"
            return "ACTIVE" if bool(rec.get("enabled")) else "DISABLED"
        if category == "BACKUP_ARCHIVE":
            if rec.get("archive_present") is False:
                return "ABSENT"
            if rec.get("restore_allowed") is None:
                return "ACTIVE"
            return "ACTIVE" if bool(rec.get("restore_allowed")) else "BLOCKED"
        return default

    def _parse_sql_row(
        self,
        fid: str,
        captured_at: str,
        table: str,
        row: Dict[str, Any],
        is_replica: bool,
        copy_label: str,
    ) -> None:
        if "record_json" in row and clean(row.get("origin_system")):
            try:
                rec = json.loads(row["record_json"])
            except Exception:
                return
            if not isinstance(rec, dict):
                return
            system = clean(row.get("origin_system"))
            collection = clean(row.get("collection_name"))
            rid = clean(row.get("resource_id")) or clean(rec.get("resource_id"))
            category = _category_for(system, collection, rid, rec)
            state = self._state_for_category(category, rec)
            observed_at = clean(row.get("updated_at")) or clean(rec.get("updated_at")) or captured_at
            uid = self.resolver.resolve_any(_record_identifier(rec))
            self.add(
                fid, captured_at, observed_at, system, rid, category, state,
                identifier=_record_identifier(rec), user_id=uid,
                source=f"sql:{table}", is_replica=is_replica, copy_label=copy_label, raw=rec,
            )
            return

        rid = clean(row.get("resource_id") or row.get("account_id") or row.get("doc_id"))
        if not rid:
            return
        observed_at = clean(row.get("updated_at") or row.get("indexed_at") or row.get("recorded_at")) or captured_at

        if table.startswith("customer_profiles"):
            rec = dict(row)
            uid = self.resolver.resolve_any(rec.get("user_id") or rec.get("email"))
            self.add(
                fid, captured_at, observed_at, "account_service", rid, "USER_PROFILE", "PRESENT",
                identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                is_replica=is_replica, copy_label=copy_label, raw=rec,
            )
            return

        if table in ("search_documents_primary", "customer_search_index_primary"):
            rec = dict(row)
            uid = self.resolver.resolve_any(rec.get("user_id") or rec.get("email") or rec.get("source_resource_id"))
            self.add(
                fid, captured_at, observed_at, "search_service", rid, "SEARCH_INDEX_ENTRY", "PRESENT",
                identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                is_replica=is_replica, copy_label=copy_label, raw=rec,
            )
            return

        # Inventory / operational table families.
        rec = {k: (v if v is not None else "") for k, v in row.items()}
        if table == "customer_search_documents":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("email"))
            self.add(fid, captured_at, observed_at, "search_service", rid, "SEARCH_INDEX_ENTRY", "PRESENT",
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "customer_analytics_profiles":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("email"))
            state = self._state_for_category("ANALYTICS_PROFILE", rec)
            self.add(fid, captured_at, observed_at, "analytics_platform", rid, "ANALYTICS_PROFILE", state,
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "support_records":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("requester_email"))
            state = self._state_for_category("SUPPORT_MESSAGE", rec)
            self.add(fid, captured_at, observed_at, "support_platform", rid, "SUPPORT_MESSAGE", state,
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "customer_exports":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("owner_email"))
            self.add(fid, captured_at, observed_at, "export_service", rid, "USER_EXPORT", "PRESENT",
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "connector_subscriptions":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("customer_email"))
            state = self._state_for_category("DATA_FLOW", rec)
            self.add(fid, captured_at, observed_at, "integration_service", rid, "DATA_FLOW", state,
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "backup_restore_entries":
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("customer_email"))
            state = self._state_for_category("BACKUP_ARCHIVE", rec)
            self.add(fid, captured_at, observed_at, "backup_service", rid, "BACKUP_ARCHIVE", state,
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table == "security_audit_records":
            uid = self.resolver.resolve_any(rec.get("subject_reference"))
            self.add(fid, captured_at, observed_at, "security_service", rid, "SECURITY_AUDIT_LOG", "PRESENT",
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)
        elif table.startswith("marketing"):
            uid = self.resolver.resolve_any(rec.get("customer_reference") or rec.get("email"))
            self.add(fid, captured_at, observed_at, "marketing_platform", rid, "MARKETING_PROFILE", "PRESENT",
                     identifier=_record_identifier(rec), user_id=uid, source=f"sql:{table}",
                     is_replica=is_replica, copy_label=copy_label, raw=rec)

    # -- JSON -------------------------------------------------------------
    def _parse_json(self, fid: str, path: Path, captured_at: str) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return

        if isinstance(data.get("snapshots"), list):
            for snap in data["snapshots"]:
                ts = clean(snap.get("captured_at")) or clean(data.get("exported_at")) or captured_at
                store = clean(snap.get("data_store"))
                coll = clean(snap.get("collection"))
                seq: List[Optional[Observation]] = []
                for rec in snap.get("records") or []:
                    if not isinstance(rec, dict):
                        seq.append(None)
                        continue
                    obs = self._parse_collection_record(fid, captured_at, ts, store, coll, rec, source="json:snapshot")
                    seq.append(obs)
                self.snapshot_sequences.append({
                    "file_id": fid, "captured_at": captured_at, "observed_at": ts,
                    "store": store, "collection": coll, "observations": seq,
                })
            return

        if isinstance(data.get("service_exports"), dict):
            self._parse_service_exports(fid, captured_at, data["service_exports"])
            return

        if isinstance(data.get("records"), list):
            coll = clean(data.get("collection"))
            ts = clean(data.get("captured_at") or data.get("exported_at")) or captured_at
            store = clean(data.get("source") or data.get("origin"))
            for rec in data["records"]:
                if not isinstance(rec, dict):
                    continue
                if "system" in rec and "result" in rec:
                    self._parse_summary_record(
                        fid, captured_at, clean(rec.get("recorded_at")) or ts,
                        clean(rec.get("system")), clean(rec.get("resource_id")),
                        clean(rec.get("record_type")), clean(rec.get("result")),
                        clean(rec.get("subject_reference")), source="json:summary",
                    )
                else:
                    system = store if store in ("export_service", "analytics_platform") else ""
                    self._parse_collection_record(fid, captured_at, ts, system, coll, rec, source="json:records")
            return

        if clean(data.get("resource_id")):
            self._parse_collection_record(
                fid, captured_at, clean(data.get("captured_at")) or captured_at,
                clean(data.get("source") or data.get("system_id")), clean(data.get("collection")), data,
                source="json:single",
            )

    def _parse_collection_record(
        self,
        fid: str,
        captured_at: str,
        observed_at: str,
        store: str,
        collection: str,
        rec: Dict[str, Any],
        source: str = "",
        is_replica: bool = False,
        copy_label: str = "",
    ) -> Optional[Observation]:
        rid = clean(rec.get("resource_id") or rec.get("record_id") or rec.get("export_id") or rec.get("doc_id"))
        if not rid:
            return None
        system = _infer_system(store, collection, rid, rec)
        category = _category_for(system, collection, rid, rec)
        state = self._state_for_category(category, rec)
        uid = self.resolver.resolve_any(_record_identifier(rec))
        observed = clean(rec.get("observed_at") or rec.get("recorded_at") or rec.get("updated_at") or rec.get("indexed_at")) or observed_at
        return self.add(
            fid, captured_at, observed, system, rid, category, state,
            identifier=_record_identifier(rec), user_id=uid, source=source,
            is_replica=is_replica, copy_label=copy_label, raw=rec,
        )

    def _parse_service_exports(self, fid: str, captured_at: str, exports: Dict[str, Any]) -> None:
        for system, groups in exports.items():
            if not isinstance(groups, dict):
                continue
            for group, rows in groups.items():
                if not isinstance(rows, list):
                    continue
                for rec in rows:
                    if not isinstance(rec, dict):
                        continue
                    rid = clean(rec.get("resource_id"))
                    observed = clean(rec.get("observed_at")) or captured_at
                    if not rid:
                        continue

                    if system == "account_service" and "profile" in rec:
                        profile = rec.get("profile") or {}
                        status = str(rec.get("status_code") or "")
                        absent = rec.get("profile") is None or status == "404"
                        self.add(
                            fid, captured_at, observed, "account_service", rid, "USER_PROFILE",
                            "ABSENT" if absent else "PRESENT",
                            identifier=_record_identifier(profile) if isinstance(profile, dict) else "",
                            source="json:service_export", raw=rec,
                        )
                        continue

                    if system == "search_service" and "hits" in rec:
                        hits = rec.get("hits") or {}
                        docs = hits.get("documents") if isinstance(hits, dict) else None
                        if isinstance(docs, list) and docs:
                            for idx, doc in enumerate(docs):
                                doc_rid = clean(doc.get("resource_id")) or rid
                                self.add(
                                    fid, captured_at, observed, "search_service", doc_rid,
                                    "SEARCH_INDEX_ENTRY", "PRESENT", identifier=_record_identifier(doc),
                                    source="json:service_export", raw=doc,
                                )
                        else:
                            self.add(
                                fid, captured_at, observed, "search_service", rid, "SEARCH_INDEX_ENTRY",
                                "ABSENT" if str(hits.get("total", 1)) == "0" else "PRESENT",
                                identifier=clean(rec.get("query")), source="json:service_export", raw=rec,
                            )
                        continue

                    category = _category_for(system, group, rid, rec)
                    state = self._state_for_category(category, rec)
                    self.add(
                        fid, captured_at, observed, system, rid, category, state,
                        identifier=_record_identifier(rec), source="json:service_export", raw=rec,
                    )

    def _parse_summary_record(
        self,
        fid: str,
        captured_at: str,
        observed_at: str,
        system: str,
        rid: str,
        record_type: str,
        result: str,
        subject: str,
        source: str = "",
    ) -> Optional[Observation]:
        if not rid:
            return None
        rtype = clean(record_type).upper()
        res = clean(result).upper()
        category = rtype if rtype else _category_for(system, "", rid, {})
        if category == "DATA_FLOW":
            state = "ACTIVE" if res in ("ACTIVE", "ENABLED", "FOUND", "PRESENT") else "DISABLED"
        elif category == "BACKUP_ARCHIVE":
            if res in ("ACTIVE", "ENABLED", "FOUND", "PRESENT"):
                state = "ACTIVE"
            elif res in ("BLOCKED", "DISABLED"):
                state = "BLOCKED"
            else:
                state = "ABSENT"
        elif category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            state = "ANONYMIZED" if res in ("ANONYMIZED", "ABSENT") else "PRESENT"
        elif category == "ACCOUNT_TOMBSTONE":
            state = "REDACTED" if res in ("REDACTED", "ANONYMIZED") else "PRESENT"
        elif category == "SUPPORT_MESSAGE":
            state = "REDACTED" if res in ("REDACTED", "ABSENT") else "PRESENT"
        elif category in ("SUPPORT_ATTACHMENT", "USER_EXPORT", "USER_PROFILE", "SEARCH_INDEX_ENTRY", "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY", "EMAIL_DELIVERY_LOG"):
            state = "PRESENT" if res in ("FOUND", "PRESENT", "HIT", "READY", "AVAILABLE", "IDENTIFIABLE") else "ABSENT"
        else:
            state = "PRESENT" if res in ("FOUND", "PRESENT", "ACTIVE", "IDENTIFIABLE") else "ABSENT"
        return self.add(
            fid, captured_at, observed_at, system, rid, category, state,
            identifier=subject, source=source or "summary", raw={"subject_reference": subject, "result": result},
        )

    # -- logs / text ------------------------------------------------------
    def _parse_text_log(self, fid: str, path: Path, captured_at: str) -> None:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        handover = [ln for ln in lines if ln.strip().startswith("-") and ln.count("|") >= 5]
        if handover:
            for ln in handover:
                parts = [p.strip() for p in ln.strip().lstrip("-").split("|")]
                if len(parts) >= 6:
                    ts, system, rid, rtype, result, subject = parts[:6]
                    self._parse_summary_record(fid, captured_at, ts, system, rid, rtype, result, subject, "text:handover")
            return

        parsed: List[Tuple[str, Dict[str, str]]] = []
        trace_key: Dict[str, str] = {}
        for line in lines:
            row = self._parse_log_line(line)
            if not row:
                continue
            ts, kv = row
            tid = clean(kv.get("trace_id") or kv.get("requestId") or kv.get("request_id"))
            if tid:
                kv["trace_id"] = tid
                for key in (
                    "lookup_key", "match_key", "subject_key", "scan_key", "owner_key",
                    "subject_ref", "correlation_key", "subject_reference", "email",
                    "customer_reference", "requester_email",
                ):
                    val = clean(kv.get(key))
                    if val:
                        trace_key.setdefault(tid, val)
            parsed.append((ts, kv))

        for ts, kv in parsed:
            self._interpret_log_event(fid, captured_at, ts, kv, trace_key)

    def _parse_log_line(self, line: str) -> Optional[Tuple[str, Dict[str, str]]]:
        s = line.strip()
        if not s:
            return None
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s*(.*)$", s)
        if not m:
            return None
        ts, rest = m.group(1), m.group(2).strip()
        kv: Dict[str, str] = {}

        if rest.startswith("{") and rest.endswith("}"):
            try:
                obj = json.loads(rest)
                kv = {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
                rest = ""
            except Exception:
                pass

        if rest:
            m_sys = re.match(r"^<\d+>1\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$", rest)
            m_br = re.match(r"^\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([A-Za-z0-9_]+):?\s*(.*)$", rest)
            if rest.startswith("|"):
                segs = [p.strip() for p in rest.lstrip("|").split("|")]
                if len(segs) >= 4:
                    kv.setdefault("level", segs[0])
                    kv.setdefault("service", segs[1])
                    kv.setdefault("trace_id", segs[2])
                    kv.setdefault("event", segs[3])
                    rest = " | ".join(segs[4:])
            elif m_sys:
                kv.setdefault("service", m_sys.group(1))
                kv.setdefault("trace_id", m_sys.group(2))
                rest = m_sys.group(3)
            elif m_br:
                kv.setdefault("level", m_br.group(1))
                kv.setdefault("service", m_br.group(2))
                kv.setdefault("trace_id", m_br.group(3))
                kv.setdefault("event", m_br.group(4))
                rest = m_br.group(5)

            # cloud runtime wraps a logfmt message in an escaped quoted string
            if 'message="' in rest:
                msg = re.search(r'message="((?:\\.|[^"\\])*)"', rest)
                if msg:
                    inner = msg.group(1).replace('\\"', '"').replace("\\n", " ")
                    if inner.startswith("{") and inner.endswith("}"):
                        try:
                            obj = json.loads(inner)
                            for k, v in obj.items():
                                kv.setdefault(str(k), "" if v is None else str(v))
                        except Exception:
                            pass
                    else:
                        for fm in re.finditer(r'([A-Za-z0-9_]+)=("[^"]*"|\S+)', inner):
                            kv.setdefault(fm.group(1), fm.group(2).strip('"'))

            for fm in re.finditer(r'([A-Za-z0-9_]+)=("[^"]*"|\S+)', rest):
                kv.setdefault(fm.group(1), fm.group(2).strip('"'))

        if not kv:
            return None
        kv = {k: clean(v) for k, v in kv.items() if v is not None}
        return ts, kv

    def _interpret_log_event(self, fid: str, captured_at: str, ts: str, kv: Dict[str, str], trace_key: Dict[str, str]) -> None:
        event = clean(kv.get("event"))
        system = clean(kv.get("system") or kv.get("service") or kv.get("logger") or kv.get("function"))
        if system == "profile_service":
            system = "account_service"
        rid = clean(kv.get("resource_id"))
        if not rid:
            return

        raw_key = ""
        for key in (
            "matched_value", "subject_reference", "subject_ref", "requester_email",
            "customer_email", "email", "customer_reference", "lookup_key",
            "correlation_key", "owner_key", "scan_key",
        ):
            if clean(kv.get(key)):
                raw_key = clean(kv.get(key))
                break
        if not raw_key:
            raw_key = trace_key.get(clean(kv.get("trace_id")), "")

        if event == "record_lookup":
            self._parse_summary_record(
                fid, captured_at, ts, clean(kv.get("system")), rid,
                clean(kv.get("record_type")), clean(kv.get("result")), raw_key, "log:record_lookup",
            )
            return

        if system == "account_service" and event == "profile_lookup_completed":
            absent = clean(kv.get("http_status")) == "404" or clean(kv.get("rows")) == "0"
            self.add(fid, captured_at, ts, "account_service", rid, "USER_PROFILE",
                     "ABSENT" if absent else "PRESENT", identifier=raw_key, source="log", raw=kv)
        elif system == "search_service" and event == "index_query_completed":
            hit = clean(kv.get("result")).lower() == "hit" or clean(kv.get("total_hits")) not in ("", "0")
            self.add(fid, captured_at, ts, "search_service", rid, "SEARCH_INDEX_ENTRY",
                     "PRESENT" if hit else "ABSENT", identifier=raw_key, source="log", raw=kv)
        elif system == "security_service" and event in ("audit_record_read_completed", "audit_record_query_completed"):
            rows = clean(kv.get("rows"))
            if rows == "0":
                return
            self.add(fid, captured_at, ts, "security_service", rid, "SECURITY_AUDIT_LOG", "PRESENT",
                     identifier=raw_key, source="log", raw=kv)
        elif system == "legal_service" and event == "retained_order_loaded":
            self.add(fid, captured_at, ts, "legal_service", rid, "LEGAL_HOLD_RECORD", "PRESENT",
                     identifier=raw_key, source="log", raw=kv)
        elif system == "analytics_platform":
            if event == "contact_lookup_completed":
                hit = clean(kv.get("rows")) not in ("", "0") or clean(kv.get("result")).lower() == "hit"
                self.add(fid, captured_at, ts, "analytics_platform", rid, "SECONDARY_IDENTIFIER",
                         "PRESENT" if hit else "ABSENT", identifier=raw_key, source="log", raw=kv)
            elif event in ("analytics_identity_scan", "analytics_profile_scan_completed"):
                self.add(fid, captured_at, ts, "analytics_platform", rid, "ANALYTICS_PROFILE", "PRESENT",
                         identifier=raw_key, source="log", raw=kv)
            elif event in ("analytics_profile_read", "analytics_profile_read_completed"):
                has_pii = bool(clean(kv.get("direct_identifiers")) not in ("", "0"))
                for key in ("email", "phone", "email_hash", "customer_reference", "user_id"):
                    if clean(kv.get(key)):
                        has_pii = True
                self.add(fid, captured_at, ts, "analytics_platform", rid, "ANALYTICS_PROFILE",
                         "PRESENT" if has_pii else "ANONYMIZED", identifier=raw_key, source="log", raw=kv)
        elif system in ("support_platform", "support_replica"):
            if event in ("contact_query_completed", "attachment_pii_scan", "attachment_scan_completed"):
                rows = clean(kv.get("rows"))
                state = "ABSENT" if rows == "0" else "PRESENT"
                self.add(fid, captured_at, ts, "support_platform", rid, "SUPPORT_ATTACHMENT", state,
                         identifier=raw_key, source="log", raw=kv)
            elif event == "message_pii_scan":
                self.add(fid, captured_at, ts, "support_platform", rid, "SUPPORT_MESSAGE", "PRESENT",
                         identifier=raw_key, source="log", raw=kv)
            elif event == "message_read":
                text = clean(kv.get("message_text"))
                state = "REDACTED" if text.strip().lower() == "[redacted]" else "PRESENT"
                self.add(fid, captured_at, ts, "support_platform", rid, "SUPPORT_MESSAGE", state,
                         identifier=raw_key, source="log", raw=kv)
            elif event == "support_ticket_read_completed":
                has_pii = any(clean(kv.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
                self.add(fid, captured_at, ts, "support_platform", rid, "SUPPORT_MESSAGE",
                         "PRESENT" if has_pii else "REDACTED", identifier=raw_key, source="log", raw=kv)
        elif system == "integration_service" and event in ("connector_config_read_completed", "connector_heartbeat", "connector_config_loaded"):
            enabled = clean(kv.get("enabled")).lower() == "true"
            if clean(kv.get("enabled")) == "":
                enabled = clean(kv.get("last_delivery_status")).lower() != "stopped"
            self.add(fid, captured_at, ts, "integration_service", rid, "DATA_FLOW",
                     "ACTIVE" if enabled else "DISABLED", identifier=raw_key, source="log", raw=kv)
        elif system == "backup_service" and event in ("restore_policy_read_completed", "restore_candidate_evaluated", "restore_authorization_completed", "restore_policy_check_completed"):
            if event == "restore_candidate_evaluated":
                active = clean(kv.get("eligible")).lower() == "true" and clean(kv.get("deletion_block")).lower() != "true"
            elif event == "restore_authorization_completed":
                active = clean(kv.get("decision")).lower() != "deny"
            else:
                active = clean(kv.get("restore_allowed")).lower() == "true"
            if clean(kv.get("archive_present")).lower() == "false":
                return
            self.add(fid, captured_at, ts, "backup_service", rid, "BACKUP_ARCHIVE",
                     "ACTIVE" if active else "BLOCKED", identifier=raw_key, source="log", raw=kv)
        elif system == "export_service" and event in ("export_download_check_completed", "export_metadata_read_completed"):
            available = clean(kv.get("available")).lower() == "true"
            self.add(fid, captured_at, ts, "export_service", rid, "USER_EXPORT",
                     "PRESENT" if available else "ABSENT", identifier=raw_key, source="log", raw=kv)
        elif system == "identity_service" and event in ("tombstone_read_completed", "deleted_reference_read_completed"):
            has_pii = any(clean(kv.get(k)) for k in ("name", "email", "phone", "email_hash"))
            self.add(fid, captured_at, ts, "identity_service", rid, "ACCOUNT_TOMBSTONE",
                     "PRESENT" if has_pii else "REDACTED", identifier=raw_key, source="log", raw=kv)

    # -- PDF --------------------------------------------------------------
    def _pdf_text(self, path: Path) -> str:
        try:
            from pypdf import PdfReader  # type: ignore

            reader = PdfReader(str(path))
            pages = [page.extract_text() or "" for page in reader.pages]
            text = "\n".join(pages)
            if text.strip():
                return text
        except Exception as exc:
            self.warnings.append(f"pypdf failed for {path.name}: {exc}")
        # Minimal dependency-free fallback for FlateDecode text streams.
        raw = path.read_bytes()
        chunks: List[str] = []
        for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.DOTALL):
            try:
                decomp = zlib.decompress(match.group(1)).decode("latin-1", errors="ignore")
            except Exception:
                continue
            chunks.extend(re.findall(r"\(([^()]*)\)", decomp))
        return "\n".join(chunks)

    def _parse_pdf(self, fid: str, path: Path, captured_at: str) -> None:
        text = self._pdf_text(path)
        if not text.strip():
            self.warnings.append(f"{fid}: no extractable PDF text")
            return
        low = text.lower()
        emails = [normalize_email(e) for e in EMAIL_RE.findall(text)]
        phones = [normalize_phone(p) for p in re.findall(r"\+?\d[\d\s().-]{7,}\d", text)]
        users = USER_ID_RE.findall(text)
        resource_ids = sorted({r.lower() for r in RESOURCE_ID_RE.findall(text)})

        # Derive ids that are printed as human references rather than native ids.
        has_export = any(r.startswith("export_") for r in resource_ids)
        has_support = any(r.startswith("support_") for r in resource_ids)
        if not has_export:
            for ref in re.findall(r"NST-\d{4}-\d{4}-(\d{3,5})", text):
                resource_ids.append(f"export_{int(ref)}")
        if not has_support:
            for ref in re.findall(r"\bCS-(\d{3,5})\b", text):
                resource_ids.append(f"support_{int(ref)}")
        resource_ids = list(dict.fromkeys(resource_ids))

        identifiers = [e for e in emails if e] + [p for p in phones if p] + users
        # Resolve through activity aliases when the PDF prints a business reference.
        for ref in re.findall(r"[A-Z]{2,6}-\d{4}-[A-Za-z0-9-]+", text):
            for rid, aliases in self.activity_aliases.items():
                if ref.lower() in aliases:
                    resource_ids.append(rid)
        resource_ids = list(dict.fromkeys(resource_ids))

        if not resource_ids:
            return
        for rid in resource_ids:
            rid = clean(rid)
            if not rid:
                continue
            prefix = rid.split("_")[0]
            system = {
                "audit": "security_service", "support": "support_platform", "export": "export_service",
                "account": "account_service", "analytics": "analytics_platform", "legal": "legal_service",
                "tombstone": "identity_service", "backup": "backup_service", "search": "search_service",
            }.get(prefix, "")
            if prefix == "legal":
                # The finance register is context, not a legal_service record with a
                # stable resource id; only explicit legal_hold_* records are audited.
                continue
            category = _category_for(system, "", rid, {})
            state = "PRESENT"
            if system == "support_platform":
                category = "SUPPORT_ATTACHMENT" if ("attachment" in low or "address correction" in low or "delivery" in low) else "SUPPORT_MESSAGE"
            elif system == "identity_service":
                category = "ACCOUNT_TOMBSTONE"
                state = "PRESENT" if emails else "REDACTED"
            identifier = identifiers[0] if identifiers else ""
            self.add(
                fid, captured_at, captured_at, system, rid, category, state,
                identifier=identifier, source="pdf", raw={"text_excerpt": text[:500]},
            )

    # -- images / OCR -----------------------------------------------------
    def _ocr_boxes(self, path: Path) -> List[Dict[str, Any]]:
        raw = path.read_bytes()
        cache_path = None
        if self.ocr_cache is not None:
            key = hashlib.sha256(raw).hexdigest()
            cache_path = Path(self.ocr_cache) / f"{key}.json"
            if cache_path.exists():
                try:
                    return json.loads(cache_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
        items: List[Dict[str, Any]] = []
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore

            if self._ocr_engine is None:
                self._ocr_engine = RapidOCR()
            result, _ = self._ocr_engine(str(path))
            for box, text, score in result or []:
                xs = [pt[0] for pt in box]
                ys = [pt[1] for pt in box]
                items.append({
                    "text": clean(text), "score": float(score),
                    "x": float(sum(xs) / len(xs)), "y": float(sum(ys) / len(ys)),
                    "x0": float(min(xs)), "x1": float(max(xs)),
                    "y0": float(min(ys)), "y1": float(max(ys)),
                })
        except Exception as exc:
            self.warnings.append(f"OCR unavailable for {path.name}: {exc}")
            try:
                import pytesseract  # type: ignore
                from PIL import Image  # type: ignore

                data = pytesseract.image_to_data(Image.open(path), output_type=pytesseract.Output.DICT)
                for i, text in enumerate(data.get("text", [])):
                    if clean(text):
                        items.append({
                            "text": clean(text), "score": 1.0,
                            "x": float(data["left"][i] + data["width"][i] / 2),
                            "y": float(data["top"][i] + data["height"][i] / 2),
                            "x0": float(data["left"][i]), "x1": float(data["left"][i] + data["width"][i]),
                            "y0": float(data["top"][i]), "y1": float(data["top"][i] + data["height"][i]),
                        })
            except Exception:
                pass
        if cache_path is not None and items:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
        return items

    @staticmethod
    def _detect_ui_system(text: str) -> str:
        low = text.lower().replace(" ", "")
        rules = [
            ("pulseanalytics", "analytics_platform"),
            ("vaultrecovery", "backup_service"),
            ("recoverymanager", "backup_service"),
            ("bridgeops", "integration_service"),
            ("customerdownloadcenter", "export_service"),
            ("customerreferenceregistry", "identity_service"),
            ("audienceoperations", "marketing_platform"),
            ("objectstorage", "object_storage"),
            ("searchconsole", "search_service"),
            ("sentinel", "security_service"),
            ("helplineconsole", "support_platform"),
            ("customeroperations", "account_service"),
        ]
        for needle, system in rules:
            if needle in low:
                return system
        return ""

    def _parse_image(self, fid: str, path: Path, captured_at: str) -> None:
        boxes = self._ocr_boxes(path)
        if not boxes:
            return
        full = " ".join(b["text"] for b in boxes)
        flat = re.sub(r"\s+", "", full).lower()
        system = self._detect_ui_system(full)
        width = max((b["x1"] for b in boxes), default=1800.0)
        height = max((b["y1"] for b in boxes), default=1200.0)
        emails = [normalize_email(e) for e in EMAIL_RE.findall(full)]
        emails = [e for e in emails if e]
        users = USER_ID_RE.findall(full)
        phones = _extract_phones_strict(full)

        candidate_ids: Set[str] = set(r.lower() for r in RESOURCE_ID_RE.findall(full)) | _fuzzy_resource_ids(full)
        # Business references shown on screen often resolve through the data catalog.
        for rid, aliases in self.activity_aliases.items():
            for alias in aliases:
                if len(alias) >= 6 and alias in flat and (rid.lower() in alias or "." in alias or "-" in alias):
                    candidate_ids.add(rid)
        if system == "identity_service":
            for uid in users:
                candidate_ids.update(self.user_alias_resources.get(uid.lower(), set()))

        def score(rid: str) -> float:
            total = 0.0
            prefix = rid.split("_")[0]
            expected = {
                "account_service": "account", "analytics_platform": "analytics",
                "backup_service": "backup", "integration_service": "data_flow",
                "export_service": "export", "identity_service": "tombstone",
                "marketing_platform": "marketing", "object_storage": "object",
                "search_service": "search", "security_service": "audit_record",
                "support_platform": "support",
            }.get(system, "")
            if prefix == expected:
                total += 5
            if rid in full.lower() or rid in flat:
                total += 2
            for b in boxes:
                token = b["text"].lower().replace(" ", "")
                digit_table = str.maketrans({"o": "0", "l": "1", "i": "1"})
                token_norm = re.sub(r"_[0-9oOlIi]+", lambda m: "_" + m.group(0)[1:].translate(digit_table), token)
                if rid in token or rid in token_norm or (prefix == "object" and any(a in token for a in self.activity_aliases.get(rid, set()) if len(a) > 6)):
                    if b["x"] > width * 0.70 and b["y"] < height * 0.34:
                        total += 12  # detail panel identifies the selected record
                    elif b["y"] < height * 0.24:
                        total += 7
                    elif b["y"] > height * 0.35:
                        total += 1
                    if any(uid.lower() in token for uid in users) and rid in token:
                        total += 6
            return total

        if not candidate_ids:
            return
        rid = max(candidate_ids, key=score)
        if score(rid) <= 0:
            return

        low = full.lower()
        rid_y = next((b["y"] for b in boxes if rid in b["text"].lower().replace(" ", "")), None)
        selected_text = " ".join(
            b["text"] for b in boxes if rid_y is not None and abs(b["y"] - rid_y) < 22
        ).lower()

        category = _category_for(system, "", rid, {})
        state = "PRESENT"
        if system == "account_service":
            category = "USER_PROFILE"
            if "retained reference" in low and not emails and not phones:
                category, state = "ACCOUNT_TOMBSTONE", "PRESENT"
        elif system == "analytics_platform":
            category = "ANALYTICS_PROFILE"
        elif system == "backup_service":
            category = "BACKUP_ARCHIVE"
            state = "BLOCKED" if re.search(r"restore\s*blocked|blocked|disabled", low) else "ACTIVE"
        elif system == "integration_service":
            category = "DATA_FLOW"
            state = "DISABLED" if re.search(r"\bdisabled\b|\bstopped\b|\binactive\b", low) else "ACTIVE"
        elif system == "export_service":
            category = "USER_EXPORT"
            if re.search(r"\bready\b|\bavailable\b|\bcompleted\b", selected_text):
                state = "PRESENT"
            elif re.search(r"\bexpired\b|\bdeleted\b|download\s*unavailable", selected_text):
                state = "ABSENT"
            else:
                state = "PRESENT"
        elif system == "identity_service":
            category = "ACCOUNT_TOMBSTONE"
            has_pii = bool(emails) or any(self.resolver.resolve_any(p) for p in phones)
            state = "PRESENT" if has_pii else "REDACTED"
        elif system == "marketing_platform":
            category = "MARKETING_PROFILE"
        elif system == "object_storage":
            category = "SUPPORT_ATTACHMENT"
        elif system == "search_service":
            category = "SEARCH_INDEX_ENTRY"
        elif system == "security_service":
            category = "SECURITY_AUDIT_LOG"
        elif system == "support_platform":
            category = "SUPPORT_MESSAGE"

        identifier = (emails[0] if emails else (users[0] if users else (phones[0] if phones else "")))
        raw = {"ocr_text": full[:800]}
        expires = re.search(r"expires?\s*[: ]?\s*([0-9]{1,2}\s+[A-Za-z]{3}\s+20[0-9]{2}[^\n]{0,20})", full, re.IGNORECASE)
        if expires:
            raw["expires_at_text"] = clean(expires.group(1))
        self.add(fid, captured_at, captured_at, system or "unknown_service", rid, category, state,
                 identifier=identifier, source="image:ocr", raw=raw)

    def _parse_csv_records(self, fid: str, path: Path, captured_at: str) -> None:
        import csv as _csv

        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            for row in _csv.DictReader(fh):
                rid = clean(row.get("resource_id") or row.get("record_id"))
                if not rid:
                    continue
                system = clean(row.get("system") or row.get("system_id"))
                if not system:
                    continue
                self._parse_collection_record(
                    fid, captured_at, clean(row.get("observed_at") or row.get("updated_at")) or captured_at,
                    system, clean(row.get("collection")), row, source="csv",
                )

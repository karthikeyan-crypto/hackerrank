"""Shared data model, ordering rules, and normalization helpers."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set

PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

OPERATION_ORDER: Dict[str, Dict[str, int]] = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 1,
        "REPORT_EXPOSED_PII": 2,
        "REPORT_ACTIVE_DATA_FLOW": 3,
        "REPORT_RESTORE_RISK": 4,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 1,
        "BLOCK_RESTORE": 2,
        "DELETE_RECORD": 3,
        "REDACT_RECORD": 4,
        "ANONYMIZE_RECORD": 5,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 1,
        "VERIFY_RECORD_PRESENT": 2,
        "VERIFY_RECORD_REDACTED": 3,
        "VERIFY_RECORD_ANONYMIZED": 4,
        "VERIFY_DATA_FLOW_DISABLED": 5,
        "VERIFY_RESTORE_BLOCKED": 6,
    },
}

OPERATION_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Canonical fallback when deletion_rules.csv is unavailable.  Runtime behavior is
# derived from deletion_rules.csv whenever that file is present.
DEFAULT_ACTION_BY_CATEGORY = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
}

# Categories whose existence must be proven absent after deletion.
DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
}

RESOURCE_PREFIX_CATEGORY = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "support": "SUPPORT_MESSAGE",
    "export": "USER_EXPORT",
    "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "marketing": "MARKETING_PROFILE",
    "cache": "CACHE_ENTRY",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "object": "SUPPORT_ATTACHMENT",
    "product_telemetry": "PRODUCT_TELEMETRY",
}

RESOURCE_ID_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|"
    r"tombstone|legal_hold|marketing|cache|email_delivery|object|product_telemetry)_\d+\b",
    re.IGNORECASE,
)
USER_ID_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

NULLISH = {"", "null", "none", "n/a", "na", "-", "--", "—", "unknown", "not available"}


def clean(value) -> str:
    """Return a stripped string, mapping JSON null-ish values to ''."""
    if value is None:
        return ""
    s = str(value).strip().strip('"').strip("'").strip()
    return "" if s.lower() in NULLISH else s


def normalize_email(value) -> str:
    s = clean(value).lower()
    if not s or "@" not in s:
        return ""
    return s.strip(".,;:<>()[]\"'")


def normalize_phone(value) -> str:
    s = clean(value)
    if not s:
        return ""
    digits = re.sub(r"\D+", "", s)
    return digits if len(digits) >= 7 else ""


def normalize_hash(value) -> str:
    s = clean(value).lower()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    return s if re.fullmatch(r"[a-f0-9]{64}", s or "") else ""


def normalize_name(value) -> str:
    s = clean(value).lower()
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9 ]+", " ", s).strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_iso(value: str) -> Optional[datetime]:
    s = clean(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)", s)
        if not m:
            return None
        try:
            dt = datetime.fromisoformat(m.group(1) + "T" + m.group(2) + "+00:00")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class UserIdentity:
    user_id: str
    name: str
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)


@dataclass
class Observation:
    """A normalized claim about one resource at one point in time."""

    file_id: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    category: str
    state: str  # PRESENT / ABSENT / REDACTED / ANONYMIZED / ACTIVE / DISABLED / BLOCKED
    user_id: Optional[str] = None
    identifier: str = ""
    action: str = "NONE"  # DELETE / REDACT / ANONYMIZE / RETAIN / DISABLE / BLOCK / NONE
    source: str = ""
    is_replica: bool = False
    copy_label: str = ""
    raw: Dict[str, str] = field(default_factory=dict)

    @property
    def sort_key(self):
        dt = parse_iso(self.observed_at)
        cap = parse_iso(self.captured_at)
        # At equal observation time a present/active claim wins over absence: a
        # resource seen in a newer readback is stronger evidence than a stale miss.
        strength = 1 if self.state in ("PRESENT", "ACTIVE") else 0
        floor = datetime.min.replace(tzinfo=timezone.utc)
        return (dt or floor, cap or floor, strength)

"""Policy application, point-in-time state reconstruction and step planning."""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .identity import IdentityResolver
from .linking import ActivityModel
from .model import (
    DEFAULT_ACTION_BY_CATEGORY,
    OPERATION_ORDER,
    PHASE_ORDER,
    Observation,
    clean,
    iso,
    parse_iso,
)
from .parsers import EvidenceCorpus

SUPPORTED_CATEGORIES = set(DEFAULT_ACTION_BY_CATEGORY) | {"DATA_FLOW"}

FINAL_OPERATION = {
    "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
    "DISABLE": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    "BLOCK": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}

FINDING_OPERATION = {
    "DELETE": "REPORT_REMAINING_RECORD",
    "REDACT": "REPORT_EXPOSED_PII",
    "ANONYMIZE": "REPORT_EXPOSED_PII",
    "DISABLE": "REPORT_ACTIVE_DATA_FLOW",
    "BLOCK": "REPORT_RESTORE_RISK",
}

REMEDIATION_OPERATION = {
    "DELETE": ("DELETE_RECORD", "ABSENT"),
    "REDACT": ("REDACT_RECORD", "REDACTED"),
    "ANONYMIZE": ("ANONYMIZE_RECORD", "ANONYMIZED"),
    "DISABLE": ("DISABLE_DATA_FLOW", "DISABLED"),
    "BLOCK": ("BLOCK_RESTORE", "BLOCKED"),
}


class RequestClassifier:
    """Decides whether a free-text request actually authorizes deletion."""

    NON_DELETION_PATTERNS = [
        r"\bcopy of (the |my )?(personal |account )?data\b",
        r"\bexport of my\b",
        r"\bdownloadable? (copy|archive|export|package)\b",
        r"\bdata portability\b",
        r"\bprovide a copy\b",
        r"\bsend me a copy\b",
        r"\brequest(ing)? a copy\b",
        r"\brequesting access to\b",
        r"\bwhat personal data you hold\b",
        r"\bcopia de (mis datos|la informaci[oó]n)\b",
        r"\bdescargar mis datos\b",
        r"\bcopie de mes donn[eé]es\b",
        r"\bexporter mes donn[eé]es\b",
        r"\bkopie meiner (personenbezogenen )?daten\b",
        r"\bc[oó]pia dos meus dados\b",
        r"\bcopia dei miei dati\b",
        r"\bkopie van mijn gegevens\b",
        r"データのコピー",
        r"エクスポート",
        r"\bunsubscribe\b.*\b(newsletter|promotional|marketing)\b",
        r"\b(stop sending|opt me out of|remove me from)\b.*\b(marketing|promotional|newsletter)\b",
        r"\bkeep my (shopping )?account (active|open)\b",
        r"\bdo not (delete|close) my account\b",
        r"\bwithout (deleting|closing) my account\b",
        r"\bd[eé]sabonner\b",
        r"\bdarme de baja\b.*\b(bolet[ií]n|marketing|promocionales)\b",
        r"\bmarketing-e-mails abbestellen\b",
        r"\bcancelar a inscri[cç][aã]o\b",
        r"\b(update|change|correct|modify) my (email|phone|shipping address|billing address|contact details|telephone)\b",
        r"\bcorregir mi (direcci[oó]n|correo|tel[eé]fono)\b",
        r"\bactualizar mi (direcci[oó]n|correo|tel[eé]fono)\b",
        r"\bmodifier mon (adresse|num[eé]ro|e-mail)\b",
        r"\bmeine (adresse|telefonnummer|e-mail-adresse) ([aä]ndern|aktualisieren|korrigieren)\b",
        r"\batualizar meu (endere[cç]o|telefone|e-mail)\b",
        r"住所の変更",
        r"メールアドレスの変更",
        r"\b(tax|VAT|billing) (invoice|receipt|statement)\b",
        r"\breceipt for order\b",
        r"\bhow long do you retain\b",
        r"\bwhat is your retention policy\b",
    ]

    DELETION_PATTERNS = [
        r"\b(delete|erase|remove|close|purge|terminate|wipe)\b.*\b(account|profile|personal data|personal details|personal information|records)\b",
        r"\bdeleting (my |this |the )?(account|profile|it)\b",
        r"\b(deletion|erasure) of (my |this |the )?(account|profile|personal data)\b",
        r"\bremove that search result\b",
        r"\b(profile|account)( page)? is gone\b",
        r"\bbefore deleting\b",
        r"\bremaining records cannot identify me\b",
        r"\b(account|profile|personal data)\b.*\b(deleted|erased|removed|closed|purged)\b",
        r"\brequest for permanent account deletion\b",
        r"\bfull deletion\b",
        r"\bright to erasure\b",
        r"\beliminar mi cuenta\b",
        r"\bborrar (mi cuenta|mis datos)\b",
        r"\beliminaci[oó]n\b.*\b(cuenta|datos)\b",
        r"\bsupprimer (mon compte|mes donn[eé]es)\b",
        r"\bsuppression (d[eé]finitive )?(du compte|de mon compte|de mes donn[eé]es)\b",
        r"\beffacer mes donn[eé]es\b",
        r"\b(mein konto|meine daten)\b.*\bl[oö]schen\b",
        r"\bl[oö]schung meines kontos\b",
        r"\b(excluir|apagar|encerrar) (minha conta|meus dados)\b",
        r"\bexclus[aã]o da (minha )?conta\b",
        r"\b(cancellare|eliminare) (il mio account|i miei dati)\b",
        r"\b(verwijder|sluit) (mijn account|mijn gegevens)\b",
        r"アカウント.*削除",
        r"削除を依頼",
        r"個人データ.*削除",
        r"계정.*삭제",
        r"삭제해",
    ]

    def __init__(self, activity_rows: Optional[List[Dict[str, str]]] = None) -> None:
        self.activity_rows = activity_rows or []

    def authorizes_deletion(self, text: str) -> bool:
        text = clean(text)
        if not text:
            return False
        keep = re.search(
            r"\b(keep my (shopping )?account|keep the account as it is|leave (my profile|the account)|"
            r"do not (delete|close|erase|remove) (my |the |this )?account|don't delete or change anything|"
            r"not asking for deletion|not a request to (erase|delete)|information request|"
            r"without (deleting|closing|removing) (my account|any of my records)|"
            r"want to continue using the service|remove me from marketing lists only|"
            r"still want receipts and service messages|still need the account|"
            r"conserver mon compte|mantener mi cuenta activa|mein konto behalten|manter minha conta ativa|"
            r"アカウントはそのまま|계정은 유지)\b",
            text,
            re.IGNORECASE,
        )
        if keep:
            return False
        for pat in self.DELETION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return True
        for pat in self.NON_DELETION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return False
        lower = text.lower()
        return any(
            keyword in lower
            for keyword in (
                "delete", "deletion", "erase", "erasure", "remove my", "remove the profile",
                "close my account", "closed my account", "eliminar", "eliminación", "borrar",
                "supprimer", "suppression", "effacer", "löschen", "löschung", "excluir",
                "exclusão", "apagar", "cancellare", "eliminare", "verwijderen", "削除", "삭제",
                "usunąć", "usunięcie", "radera", "slet", "poista",
            )
        )


class Policy:
    """Deletion policy loaded from deletion_rules.csv."""

    def __init__(self, rules_rows: List[Dict[str, str]]) -> None:
        self.actions: Dict[str, str] = dict(DEFAULT_ACTION_BY_CATEGORY)
        self.rules: List[Dict[str, str]] = rules_rows
        for row in rules_rows:
            category = clean(row.get("data_category")).upper()
            action = clean(row.get("required_action")).upper()
            if category and action:
                self.actions[category] = action

    def action_for(self, category: str) -> str:
        if category == "DATA_FLOW":
            return "DISABLE"
        if category == "BACKUP_ARCHIVE":
            return "BLOCK"
        return self.actions.get(category, "NONE")

    def is_present_violation(self, action: str, state: str) -> bool:
        if action == "DELETE":
            return state == "PRESENT"
        if action in ("REDACT", "ANONYMIZE"):
            return state == "PRESENT"
        if action == "DISABLE":
            return state == "ACTIVE"
        if action == "BLOCK":
            return state == "ACTIVE"
        return False


class AuditEngine:
    def __init__(
        self,
        corpus: EvidenceCorpus,
        activity: ActivityModel,
        policy: Policy,
        resolver: IdentityResolver,
        classifier: RequestClassifier,
    ) -> None:
        self.corpus = corpus
        self.activity = activity
        self.policy = policy
        self.resolver = resolver
        self.classifier = classifier
        self.by_resource: Dict[str, List[Observation]] = defaultdict(list)
        self._current_reported_at = ""
        for obs in corpus.observations:
            self.by_resource[obs.resource_id].append(obs)

    # -- point-in-time reconstruction ------------------------------------
    def _resource_observations(self, user_id: str) -> Dict[str, List[Observation]]:
        result: Dict[str, List[Observation]] = defaultdict(list)
        for obs in self.corpus.observations:
            if obs.user_id != user_id:
                continue
            if obs.category not in SUPPORTED_CATEGORIES:
                continue
            result[obs.resource_id].append(obs)
        return result

    @staticmethod
    def _expired(obs: Observation, audit_dt: Optional[datetime]) -> bool:
        if not audit_dt:
            return False
        raw = obs.raw or {}
        candidates = [clean(raw.get("expires_at")), clean(raw.get("expires_at_text"))]
        for text in candidates:
            if not text:
                continue
            dt = None
            m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", text)
            if m:
                dt = parse_iso(m.group(1))
            if not dt:
                m = re.search(r"(\d{1,2})\s+([A-Za-z]{3})\w*\s+(\d{4})\s+(\d{1,2}):(\d{2})", text)
                if m:
                    try:
                        dt = datetime.strptime(
                            f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}:{m.group(5)}",
                            "%d %b %Y %H:%M",
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        dt = None
            if dt and dt < audit_dt:
                return True
        return False

    def _activity_state(self, rid: str, category: str, requested_dt: Optional[datetime], audit_dt: Optional[datetime]) -> Optional[str]:
        if not requested_dt or not audit_dt:
            return None
        rows = self.activity.events(rid)
        for row in rows:
            et = self.activity.event_time(row)
            if not et or et < requested_dt or et > audit_dt:
                continue
            event = clean(row.get("event_type")).upper()
            result = clean(row.get("reported_result")).upper()
            if category == "DATA_FLOW" and event in ("SYNC_RECORD", "UPDATE_RECORD", "CHECK_DATA_FLOW"):
                details = clean(row.get("details")).lower()
                if result in ("SUCCESS", "PARTIAL") and ("enabled" in details or "repopulated" in details or "checkpoint" in details):
                    return "ACTIVE"
            if category == "BACKUP_ARCHIVE" and event == "RESTORE_BACKUP" and result in ("SUCCESS", "PARTIAL"):
                return "ACTIVE"
        return None

    def _resolve_state(
        self,
        rid: str,
        obs_list: List[Observation],
        audit_dt: Optional[datetime],
        requested_dt: Optional[datetime],
    ) -> Tuple[Optional[str], Optional[Observation], List[Observation]]:
        at_or_before = [o for o in obs_list if not audit_dt or (parse_iso(o.observed_at) or audit_dt) <= audit_dt]
        later = [o for o in obs_list if o not in at_or_before]
        candidates = at_or_before or later
        if not candidates:
            return None, None, later
        candidates.sort(key=lambda o: o.sort_key)
        latest = candidates[-1]
        state = latest.state
        category = latest.category
        # Replication drift: when a primary and a replica are observed at the same
        # instant, the copy that still holds the record proves that data remains.
        if state == "ABSENT" and at_or_before:
            latest_dt = parse_iso(latest.observed_at)
            same_time_present = [
                o for o in at_or_before
                if latest_dt and parse_iso(o.observed_at) and abs((parse_iso(o.observed_at) - latest_dt).total_seconds()) <= 1
                and o.state in ("PRESENT", "ACTIVE")
            ]
            if same_time_present:
                latest = sorted(same_time_present, key=lambda o: o.sort_key)[-1]
                state = latest.state
        if category == "USER_EXPORT" and self._expired(latest, audit_dt):
            state = "ABSENT"
        override = self._activity_state(rid, category, requested_dt, audit_dt)
        if override:
            state = override
        return state, latest, later

    def _filter_resources(
        self,
        resources: Dict[str, List[Observation]],
        request_text: str,
        requested_dt: Optional[datetime],
        audit_dt: Optional[datetime],
    ) -> Dict[str, List[Observation]]:
        filtered = dict(resources)
        # One account profile is canonical per person.  When several account ids
        # appear, the one handled by this request's deletion workflow (closest to
        # reported_at) is the record under audit; the others are stale aliases.
        account_rids = [
            rid for rid, obs in filtered.items()
            if any(o.category == "USER_PROFILE" for o in obs)
        ]
        if len(account_rids) > 1:
            reported_dt = parse_iso(clean(self._current_reported_at or ""))
            def account_score(rid: str):
                evidence = [
                    o for o in filtered[rid]
                    if audit_dt is None or (parse_iso(o.observed_at) or audit_dt) <= audit_dt
                ]
                latest = max((parse_iso(o.observed_at) or datetime.min.replace(tzinfo=timezone.utc)) for o in evidence) if evidence else None
                best = 10**12
                for row in self.activity.events(rid, ["DELETE_RECORD"]):
                    et = self.activity.event_time(row)
                    if et and reported_dt:
                        best = min(best, abs((et - reported_dt).total_seconds()))
                # Evidence visible at audit dominates; the workflow event breaks ties.
                return (0 if evidence else 1, -(latest.timestamp() if latest else 0), best)
            keep = min(account_rids, key=account_score)
            for rid in account_rids:
                if rid != keep:
                    filtered.pop(rid, None)
        # An object-storage copy of a support attachment duplicates the support
        # platform record; report the authoritative support record once.
        has_support_attachment = any(
            any(
                o.system_id == "support_platform" and o.category == "SUPPORT_ATTACHMENT"
                and (audit_dt is None or (parse_iso(o.observed_at) or audit_dt) <= audit_dt)
                for o in obs
            )
            for obs in filtered.values()
        )
        if has_support_attachment:
            for rid in list(filtered):
                if all(o.system_id == "object_storage" for o in filtered[rid]):
                    filtered.pop(rid, None)
        return filtered

    # -- case evaluation --------------------------------------------------
    def evaluate(self, req: Dict[str, str]) -> Tuple[str, List[Dict[str, Any]]]:
        request_text = clean(req.get("request_text"))
        if not self.classifier.authorizes_deletion(request_text):
            return "NOT_APPLICABLE", []
        user_id = self.resolver.resolve_any(req.get("email"))
        if not user_id:
            return "NOT_APPLICABLE", []

        audit_dt = parse_iso(clean(req.get("audit_at")))
        requested_dt = parse_iso(clean(req.get("requested_at")))
        self._current_reported_at = clean(req.get("reported_at"))
        resources = self._resource_observations(user_id)
        resources = self._filter_resources(resources, request_text, requested_dt, audit_dt)

        findings: List[Dict[str, Any]] = []
        remediations: List[Dict[str, Any]] = []
        verifications: List[Dict[str, Any]] = []
        incomplete = False
        seen_verify: Set[Tuple[str, str]] = set()

        for rid, obs_list in sorted(resources.items()):
            if self._latest_at_or_before(obs_list, audit_dt) is None:
                continue  # no evidence existed at audit_at; later data cannot change the answer
            state, latest, later = self._resolve_state(rid, obs_list, audit_dt, requested_dt)
            if state is None or latest is None:
                continue
            category = latest.category
            system = latest.system_id
            if category == "ACCOUNT_TOMBSTONE" and state == "REDACTED":
                if not re.search(r"(tombstone|deleted[- ]account|internal reference|stable reference|reference)", request_text, re.IGNORECASE):
                    continue
            action = self.policy.action_for(category)
            if action == "NONE":
                continue

            observed_before = latest in [o for o in obs_list if not audit_dt or (parse_iso(o.observed_at) or audit_dt) <= audit_dt]
            if self.policy.is_present_violation(action, state) and observed_before:
                incomplete = True
                finding_obs = self._best_citable(obs_list, audit_dt, require_violation=state)
                finding_evidence = finding_obs.file_id if finding_obs else self._activity_citation(rid, audit_dt)
                findings.append({
                    "phase": "FINDING",
                    "system_id": system,
                    "resource_id": rid,
                    "operation": FINDING_OPERATION.get(action, "REPORT_REMAINING_RECORD"),
                    "state": "PRESENT" if action != "DISABLE" and action != "BLOCK" else "ACTIVE",
                    "evidence_id": finding_evidence,
                })
                rem_op, rem_state = REMEDIATION_OPERATION.get(action, ("DELETE_RECORD", "ABSENT"))
                remediations.append({
                    "phase": "REMEDIATION",
                    "system_id": system,
                    "resource_id": rid,
                    "operation": rem_op,
                    "state": rem_state,
                    "evidence_id": "",
                })

            final_op, final_state = FINAL_OPERATION.get(action, ("VERIFY_RECORD_ABSENT", "ABSENT"))
            if (system, rid) in seen_verify:
                continue
            seen_verify.add((system, rid))
            citation = ""
            if not incomplete:
                proof = self._best_citable(obs_list, audit_dt, require_violation=final_state)
                if proof is not None:
                    citation = proof.file_id
                else:
                    citation = self._activity_citation(rid, audit_dt)
                if not citation:
                    continue  # cannot prove the state at audit_at; do not invent a check
            verifications.append({
                "phase": "VERIFICATION",
                "system_id": system,
                "resource_id": rid,
                "operation": final_op,
                "state": final_state,
                "evidence_id": citation,
            })

        if incomplete:
            for step in verifications:
                step["evidence_id"] = ""

        steps = self._order_steps(findings + remediations + verifications)
        return ("INCOMPLETE" if incomplete else "COMPLETE"), steps

    def _activity_citation(self, rid: str, audit_dt: Optional[datetime]) -> str:
        rows = self.activity.events(rid)
        usable = []
        for row in rows:
            et = self.activity.event_time(row)
            if et and (audit_dt is None or et <= audit_dt):
                usable.append(row)
        if not usable:
            return ""
        usable.sort(key=lambda r: clean(r.get("event_time")))
        return clean(usable[-1].get("activity_id"))

    def _latest_at_or_before(self, obs_list: List[Observation], audit_dt: Optional[datetime]) -> Optional[Observation]:
        candidates = [
            o for o in obs_list
            if not audit_dt or (parse_iso(o.observed_at) or audit_dt) <= audit_dt
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda o: o.sort_key)
        return candidates[-1]

    def _best_citable(
        self,
        obs_list: List[Observation],
        audit_dt: Optional[datetime],
        require_violation: Optional[str] = None,
    ) -> Optional[Observation]:
        candidates = [
            o for o in obs_list
            if not audit_dt or (parse_iso(o.observed_at) or audit_dt) <= audit_dt
        ]
        if require_violation:
            matching = [o for o in candidates if o.state == require_violation]
            if matching:
                candidates = matching
        # Prefer an artefact that physically existed at audit_at.
        within = [o for o in candidates if not audit_dt or (parse_iso(o.captured_at) or audit_dt) <= audit_dt]
        if not within:
            return None
        pool = within
        pool.sort(key=lambda o: o.sort_key)
        return pool[-1]

    @staticmethod
    def _order_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        for step in steps:
            key = (step["phase"], step["system_id"], step["resource_id"], step["operation"])
            unique[key] = step
        ordered = sorted(
            unique.values(),
            key=lambda s: (
                PHASE_ORDER[s["phase"]],
                OPERATION_ORDER[s["phase"]][s["operation"]],
                s["system_id"],
                s["resource_id"],
            ),
        )
        result = []
        for idx, step in enumerate(ordered, start=1):
            result.append({
                "step_no": idx,
                "phase": step["phase"],
                "system_id": step["system_id"],
                "resource_id": step["resource_id"],
                "operation": step["operation"],
                "state": step["state"],
                "evidence_id": step["evidence_id"],
            })
        return result

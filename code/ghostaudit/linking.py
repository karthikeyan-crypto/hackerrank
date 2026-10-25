"""Resource identity linking and cohort-based resolution of unlabelled records.

Direct links come first: identifiers inside evidence, then data-catalog link
events.  Records whose identifiers were stripped (a 404 account lookup or an
anonymized analytics profile) are resolved from the deletion workflow timeline:
the deletion-worker event and the case's reported_at provide independent,
observable anchors.  No case id or file id is special-cased.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .identity import IdentityResolver
from .model import (
    EMAIL_RE,
    USER_ID_RE,
    Observation,
    clean,
    normalize_email,
    parse_iso,
)
from .parsers import EvidenceCorpus

STATUS_TO_RESULT = {
    "COMPLETE": "SUCCESS",
    "PARTIALLY_COMPLETE": "PARTIAL",
    "NOT_STARTED": "FAILED",
}

EVENT_FOR_CATEGORY = {
    "USER_PROFILE": ("DELETE_RECORD", "account_service"),
    "ANALYTICS_PROFILE": ("ANONYMIZE_RECORD", "analytics_platform"),
    "SUPPORT_MESSAGE": ("REDACT_RECORD", "support_platform"),
    "DATA_FLOW": ("DISABLE_DATA_FLOW", "integration_service"),
    "BACKUP_ARCHIVE": ("BLOCK_RESTORE", "backup_service"),
    "SEARCH_INDEX_ENTRY": ("DELETE_RECORD", "search_service"),
    "USER_EXPORT": ("DELETE_RECORD", "export_service"),
}


class ActivityModel:
    def __init__(self, rows: List[Dict[str, str]], resolver: IdentityResolver) -> None:
        self.rows = rows
        self.resolver = resolver
        self.by_resource: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        self.links: Dict[str, str] = {}
        for row in rows:
            rid = clean(row.get("resource_id"))
            if rid:
                self.by_resource[rid].append(row)
            if clean(row.get("event_type")).upper() == "LINK_RESOURCE_IDENTITY":
                self._read_link(row)

    def _read_link(self, row: Dict[str, str]) -> None:
        rid = clean(row.get("resource_id"))
        details = clean(row.get("details"))
        if not rid:
            return
        uid = None
        m_user = USER_ID_RE.search(details)
        if m_user:
            uid = self.resolver.resolve_any(m_user.group(0))
        if not uid:
            for email in EMAIL_RE.findall(details):
                uid = self.resolver.resolve_any(email)
                if uid:
                    break
        if uid:
            self.links[rid] = uid

    def events(self, resource_id: str, event_types: Optional[Sequence[str]] = None) -> List[Dict[str, str]]:
        rows = self.by_resource.get(resource_id, [])
        if event_types:
            wanted = {e.upper() for e in event_types}
            rows = [r for r in rows if clean(r.get("event_type")).upper() in wanted]
        return sorted(rows, key=lambda r: clean(r.get("event_time")))

    def event_time(self, row: Dict[str, str]) -> Optional[datetime]:
        return parse_iso(clean(row.get("event_time")))


class LinkingEngine:
    def __init__(
        self,
        corpus: EvidenceCorpus,
        activity: ActivityModel,
        resolver: IdentityResolver,
        requests: List[Dict[str, str]],
    ) -> None:
        self.corpus = corpus
        self.activity = activity
        self.resolver = resolver
        self.requests = requests
        self.case_user: Dict[str, str] = {}
        for req in requests:
            uid = resolver.resolve_any(req.get("email"))
            if uid:
                self.case_user[clean(req.get("case_id"))] = uid
        self._cohorts: Dict[str, Dict[str, object]] = {}
        self._observed_rids: Set[str] = set()
        self._user_categories: Dict[str, Set[str]] = defaultdict(set)

    def run(self) -> None:
        self._apply_activity_links()
        self._observed_rids = {o.resource_id for o in self.corpus.observations}
        for obs in self.corpus.observations:
            if obs.user_id:
                self._user_categories[obs.user_id].add(obs.category)
        self._cohorts = self._build_cohorts()
        self._ordinal_snapshot_links()
        self._activity_links_for_unlabelled()
        self.corpus._resolve_links()

    def _apply_activity_links(self) -> None:
        for rid, uid in self.activity.links.items():
            self.corpus.resource_to_user[rid] = uid
            self.corpus.user_resources[uid].add(rid)
        for obs in self.corpus.observations:
            if obs.resource_id in self.activity.links:
                obs.user_id = self.activity.links[obs.resource_id]

    def _build_cohorts(self) -> Dict[str, Dict[str, object]]:
        groups: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        for req in self.requests:
            groups[clean(req.get("audit_at"))].append(req)
        cohorts: Dict[str, Dict[str, object]] = {}
        for audit_at, reqs in groups.items():
            users = sorted({self.case_user.get(clean(r.get("case_id"))) for r in reqs} - {None})
            if users:
                cohorts[audit_at] = {"requests": reqs, "users": users}
        return cohorts

    def _cohort_for_time(self, observed_at: str) -> Optional[Dict[str, object]]:
        dt = parse_iso(observed_at)
        if not dt:
            return None
        best = None
        best_delta = None
        for audit_at, cohort in self._cohorts.items():
            adt = parse_iso(audit_at)
            if not adt:
                continue
            delta = abs((adt - dt).total_seconds())
            if delta > 36 * 3600 or len(cohort["users"]) < 3:
                continue
            if best_delta is None or delta < best_delta:
                best, best_delta = cohort, delta
        return best

    def _ordinal_snapshot_links(self) -> None:
        for seq in self.corpus.snapshot_sequences:
            cohort = self._cohort_for_time(seq["observed_at"])
            if not cohort:
                continue
            users = list(cohort["users"])
            observations = [o for o in seq["observations"] if o is not None]
            if not observations:
                continue
            linked_users = {o.user_id for o in observations if o.user_id}
            unlinked = [o for o in observations if not o.user_id]
            # Only infer an ordinal mapping when the snapshot demonstrably covers
            # every cohort member (one record per user); otherwise a missing/extra
            # record would shift the whole alignment.
            if not unlinked or len(linked_users) + len(unlinked) != len(users):
                continue
            pointer = 0
            assignments: List[Tuple[Observation, str]] = []
            ok = True
            for obs in observations:
                if obs.user_id:
                    if obs.user_id in users:
                        pointer = max(pointer, users.index(obs.user_id) + 1)
                    continue
                while pointer < len(users) and users[pointer] in linked_users:
                    pointer += 1
                if pointer >= len(users):
                    ok = False
                    break
                assignments.append((obs, users[pointer]))
                pointer += 1
            if ok:
                for obs, uid in assignments:
                    self._assign(obs.resource_id, uid)

    def _cohort_files(self, users: Sequence[str]) -> Set[str]:
        user_set = set(users)
        return {
            fid for fid, obs_list in self.corpus.observations_by_file.items()
            if any(o.user_id in user_set for o in obs_list)
        }

    def _assign(self, resource_id: str, user_id: str) -> None:
        self.corpus.resource_to_user[resource_id] = user_id
        self.corpus.user_resources[user_id].add(resource_id)
        for obs in self.corpus.observations:
            if obs.resource_id == resource_id and not obs.user_id:
                obs.user_id = user_id
                self._user_categories[user_id].add(obs.category)
        for seq in self.corpus.snapshot_sequences:
            for obs in seq["observations"]:
                if obs is not None and obs.resource_id == resource_id and not obs.user_id:
                    obs.user_id = user_id

    def _user_has_category(self, user_id: str, category: str) -> bool:
        return category in self._user_categories.get(user_id, set())

    def _activity_links_for_unlabelled(self) -> None:
        # Per-user cohort evidence scopes account readbacks; the activity timeline
        # is matched globally so one case cannot capture another case's account.
        reqs_by_user: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        user_audit: Dict[str, set] = defaultdict(set)
        for req in self.requests:
            uid = self.case_user.get(clean(req.get("case_id")))
            if uid:
                reqs_by_user[uid].append(req)
                user_audit[uid].add(clean(req.get("audit_at")))
        users = sorted(u for u in reqs_by_user if not self._user_has_category(u, "USER_PROFILE"))
        if not users:
            return

        cohort_files_by_audit: Dict[str, Set[str]] = {}
        for audit_at, cohort in self._cohorts.items():
            cohort_files_by_audit[audit_at] = self._cohort_files(list(cohort["users"]))
        user_files: Dict[str, Set[str]] = defaultdict(set)
        for uid in users:
            for audit_at in user_audit.get(uid, set()):
                user_files[uid] |= cohort_files_by_audit.get(audit_at, set())

        all_obs_rids = self._observed_rids
        activity_only: Dict[str, Dict[str, str]] = {}
        for rid, rows in self.activity.by_resource.items():
            if self.corpus.resource_to_user.get(rid) or rid in all_obs_rids:
                continue
            matching = [
                r for r in rows
                if clean(r.get("event_type")).upper() == "DELETE_RECORD"
                and clean(r.get("target_system")) == "account_service"
            ]
            if matching:
                activity_only[rid] = matching[-1]

        pairs: List[Tuple[int, float, str, str, Dict[str, str]]] = []
        for uid in users:
            evidence_rids = {
                obs.resource_id for fid in user_files.get(uid, set())
                for obs in self.corpus.observations_by_file.get(fid, [])
                if obs.category == "USER_PROFILE" and not obs.user_id
            }
            for rid in evidence_rids:
                if self.corpus.resource_to_user.get(rid):
                    continue
                ev = None
                for row in self.activity.by_resource.get(rid, []):
                    if clean(row.get("event_type")).upper() == "DELETE_RECORD" and clean(row.get("target_system")) == "account_service":
                        ev = row
                        break
                cost = self._account_cost(uid, ev, reqs_by_user)
                if cost is not None:
                    pairs.append((0, cost, uid, rid, ev or {}))
            for rid, ev in activity_only.items():
                if self.corpus.resource_to_user.get(rid):
                    continue
                cost = self._account_cost(uid, ev, reqs_by_user)
                if cost is not None:
                    pairs.append((1, cost, uid, rid, ev))
        pairs.sort(key=lambda p: (p[0], p[1], p[2], p[3]))
        used_users: Set[str] = set()
        used_rids: Set[str] = set()
        for evidence_backed, cost, uid, rid, ev in pairs:
            if uid in used_users or rid in used_rids or cost > 6 * 3600:
                continue
            if self._user_has_category(uid, "USER_PROFILE"):
                continue
            self._assign(rid, uid)
            used_users.add(uid)
            used_rids.add(rid)
            if evidence_backed and not ev:
                continue
            if ev and rid not in self._observed_rids:
                audits = user_audit.get(uid, set())
                synth_files = {
                    fid for fid in user_files.get(uid, set())
                    if any(clean(self.corpus.manifest.get(fid, {}).get("captured_at")) <= a for a in audits)
                }
                if not synth_files and audits:
                    cap = max(audits)
                    synth_files = {
                        fid for fid, meta in self.corpus.manifest.items()
                        if clean(meta.get("captured_at")) <= cap
                        and any(o.system_id == "account_service" for o in self.corpus.observations_by_file.get(fid, []))
                    }
                self._synthesize_from_activity(rid, uid, "USER_PROFILE", ev, synth_files)

    def _account_cost(self, uid: str, ev: Optional[Dict[str, str]], reqs_by_user: Dict[str, List[Dict[str, str]]]) -> Optional[float]:
        best = None
        for req in reqs_by_user.get(uid, []):
            rep = parse_iso(clean(req.get("reported_at")))
            if not rep:
                continue
            expected = STATUS_TO_RESULT.get(clean(req.get("reported_status")))
            if ev:
                et = self.activity.event_time(ev)
                if not et:
                    continue
                delta = abs((et - rep).total_seconds())
                if delta > 6 * 3600:
                    continue
                cost = float(delta)
                result = clean(ev.get("reported_result")).upper()
                if expected and result == expected:
                    cost -= 3600
                elif expected and result in ("SUCCESS", "PARTIAL", "FAILED"):
                    cost += 1800
            else:
                cost = 5.0 * 3600
            if best is None or cost < best:
                best = cost
        return best

    def _candidates(
        self,
        category: str,
        files: Set[str],
        cohort_rids: Set[str],
        event_type: str,
        target_system: str,
        rep_times: Sequence[datetime],
    ) -> Dict[str, Optional[Dict[str, str]]]:
        candidates: Dict[str, Optional[Dict[str, str]]] = {}
        for obs in self.corpus.observations:
            if obs.category == category and not obs.user_id and obs.file_id in files:
                candidates[obs.resource_id] = None
        for rid, rows in self.activity.by_resource.items():
            if self.corpus.resource_to_user.get(rid):
                continue
            if rid not in cohort_rids and rid in self._observed_rids:
                continue
            matching = []
            for row in rows:
                if clean(row.get("event_type")).upper() != event_type:
                    continue
                if clean(row.get("target_system")) != target_system:
                    continue
                et = self.activity.event_time(row)
                if et and any(abs((et - rt).total_seconds()) <= 6 * 3600 for rt in rep_times):
                    matching.append(row)
            if matching:
                candidates.setdefault(rid, matching[-1])
        for rid in list(candidates):
            if candidates[rid] is not None:
                continue
            matching = [
                r for r in self.activity.by_resource.get(rid, [])
                if clean(r.get("event_type")).upper() == event_type
            ]
            if matching:
                candidates[rid] = matching[-1]
        return candidates

    def _elimination(
        self,
        category: str,
        users: Sequence[str],
        candidates: Dict[str, Optional[Dict[str, str]]],
        cohort_rids: Set[str],
    ) -> None:
        remaining_users = [u for u in users if not self._user_has_category(u, category)]
        remaining_rids = [
            rid for rid in candidates
            if not self.corpus.resource_to_user.get(rid) and rid in cohort_rids
        ]
        if len(remaining_users) == 1 and len(remaining_rids) == 1:
            self._assign(remaining_rids[0], remaining_users[0])

    def _synthesize_from_activity(
        self,
        rid: str,
        uid: str,
        category: str,
        event: Dict[str, str],
        files: Set[str],
    ) -> None:
        if category != "USER_PROFILE":
            return
        event_time = clean(event.get("event_time"))
        representative = None
        for fid in files:
            if representative is None:
                representative = fid
            elif clean(self.corpus.manifest.get(fid, {}).get("captured_at")) > clean(self.corpus.manifest.get(representative, {}).get("captured_at")):
                representative = fid
        if representative:
            file_id = representative
            captured_at = clean(self.corpus.manifest.get(representative, {}).get("captured_at"))
        else:
            file_id = clean(event.get("activity_id"))
            captured_at = event_time
        self.corpus.add(
            file_id, captured_at, event_time,
            "account_service", rid, "USER_PROFILE", "ABSENT",
            identifier=uid, user_id=uid, source="activity:workflow",
            raw={"reported_result": clean(event.get("reported_result"))},
        )

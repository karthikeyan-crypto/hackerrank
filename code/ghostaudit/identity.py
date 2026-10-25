"""Current and historical customer identifier resolution."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set

from .model import (
    EMAIL_RE,
    HASH_RE,
    UserIdentity,
    clean,
    normalize_email,
    normalize_hash,
    normalize_name,
    normalize_phone,
    sha256_text,
)


class IdentityResolver:
    """Resolves any current or historical identifier to a stable user_id.

    Identifiers come from user_identities.csv plus every old/new value in
    user_audit_log.csv.  Email hashes are also derived from every known email so
    hashes embedded in logs resolve even when the hash column is absent.
    """

    def __init__(self, identity_rows: List[Dict[str, str]], audit_rows: List[Dict[str, str]]) -> None:
        self.users: Dict[str, UserIdentity] = {}
        self.email_to_user: Dict[str, str] = {}
        self.phone_to_user: Dict[str, str] = {}
        self.hash_to_user: Dict[str, str] = {}
        self.name_to_users: Dict[str, List[str]] = defaultdict(list)

        for row in identity_rows:
            uid = clean(row.get("user_id"))
            if not uid:
                continue
            user = UserIdentity(user_id=uid, name=clean(row.get("name")))
            self.users[uid] = user
            self._add_identity_values(
                user,
                email=row.get("email"),
                phone=row.get("phone"),
                email_hash=row.get("email_hash"),
                name=row.get("name"),
            )

        for row in audit_rows:
            uid = clean(row.get("user_id"))
            if uid not in self.users:
                continue
            field = clean(row.get("field_name")).lower()
            user = self.users[uid]
            for value in (row.get("old_value"), row.get("new_value")):
                if field == "email":
                    self._add_identity_values(user, email=value)
                elif field == "phone":
                    self._add_identity_values(user, phone=value)
                elif field in ("email_hash", "hash"):
                    self._add_identity_values(user, email_hash=value)
                elif field == "name":
                    self._add_identity_values(user, name=value)

    def _add_identity_values(
        self,
        user: UserIdentity,
        email=None,
        phone=None,
        email_hash=None,
        name=None,
    ) -> None:
        em = normalize_email(email)
        if em:
            user.emails.add(em)
            self.email_to_user[em] = user.user_id
            for h in (email_hash, sha256_text(em)):
                nh = normalize_hash(h)
                if nh:
                    user.hashes.add(nh)
                    self.hash_to_user[nh] = user.user_id
        else:
            nh = normalize_hash(email_hash)
            if nh:
                user.hashes.add(nh)
                self.hash_to_user[nh] = user.user_id

        ph = normalize_phone(phone)
        if ph:
            user.phones.add(ph)
            self.phone_to_user[ph] = user.user_id

        nm = normalize_name(name)
        if nm and user.user_id not in self.name_to_users[nm]:
            self.name_to_users[nm].append(user.user_id)

    def resolve_any(self, value, allow_name: bool = True) -> Optional[str]:
        """Resolve an arbitrary cell/string to one user_id, if unambiguous."""
        if value is None:
            return None
        if isinstance(value, (list, tuple, set)):
            for item in value:
                uid = self.resolve_any(item, allow_name=allow_name)
                if uid:
                    return uid
            return None
        s = clean(value)
        if not s:
            return None

        if s in self.users:
            return s
        m_user = re.fullmatch(r"user_\d+", s, re.IGNORECASE)
        if m_user:
            return s.lower() if s.lower() in self.users else None

        em = normalize_email(s)
        if em and em in self.email_to_user:
            return self.email_to_user[em]

        h = normalize_hash(s)
        if h and h in self.hash_to_user:
            return self.hash_to_user[h]

        ph = normalize_phone(s)
        if ph and ph in self.phone_to_user:
            return self.phone_to_user[ph]

        # Strings that embed an identifier (log detail / conversation excerpt).
        for cand in EMAIL_RE.findall(s):
            uid = self.email_to_user.get(normalize_email(cand))
            if uid:
                return uid
        for cand in HASH_RE.findall(s):
            uid = self.hash_to_user.get(normalize_hash(cand))
            if uid:
                return uid
        for cand in re.findall(r"\+?\d[\d\s().-]{7,}\d", s):
            uid = self.phone_to_user.get(normalize_phone(cand))
            if uid:
                return uid

        if allow_name:
            nm = normalize_name(s)
            matches = self.name_to_users.get(nm, [])
            if len(matches) == 1:
                return matches[0]
        return None

    def identifiers_for(self, user_id: str) -> Dict[str, Set[str]]:
        u = self.users.get(user_id)
        if not u:
            return {"emails": set(), "phones": set(), "hashes": set()}
        return {"emails": set(u.emails), "phones": set(u.phones), "hashes": set(u.hashes)}

    def all_emails(self) -> Iterable[str]:
        return self.email_to_user.keys()

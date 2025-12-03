"""Authentication and MFA utilities for the LLM Council API.

This module provides a lightweight JSON-backed identity store with
support for OIDC/OAuth2 claim mapping, MFA factor enrollment, and
per-device session management.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import AUTH_DATA_DIR, AUTH_STATE_FILE


@dataclass
class MfaFactor:
    """Representation of an MFA factor."""

    id: str
    type: str
    label: str
    created_at: str
    verified: bool = False
    secret: Optional[str] = None
    challenge: Optional[str] = None
    last_verified_at: Optional[str] = None

    def to_public_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "created_at": self.created_at,
            "verified": self.verified,
            "last_verified_at": self.last_verified_at,
        }
        if include_secret and self.secret:
            data["secret"] = self.secret
        if self.challenge:
            data["challenge"] = self.challenge
        return data


@dataclass
class Session:
    """Representation of an authenticated session/device."""

    id: str
    user_id: str
    device_id: str
    user_agent: Optional[str]
    created_at: str
    last_active_at: str
    revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "user_agent": self.user_agent,
            "created_at": self.created_at,
            "last_active_at": self.last_active_at,
            "revoked": self.revoked,
        }


@dataclass
class User:
    """Representation of an internal user record."""

    id: str
    username: str
    email: str
    oidc_issuer: Optional[str]
    oidc_subject: Optional[str]
    attributes: Dict[str, Any]
    mfa_factors: List[MfaFactor]

    def to_public_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "oidc_issuer": self.oidc_issuer,
            "oidc_subject": self.oidc_subject,
            "attributes": self.attributes,
            "mfa_factors": [factor.to_public_dict(include_secret=include_secrets) for factor in self.mfa_factors],
        }


# -----------------------------
# Persistence helpers
# -----------------------------


def _default_state() -> Dict[str, Any]:
    return {"users": [], "sessions": []}


def _ensure_storage():
    Path(AUTH_DATA_DIR).mkdir(parents=True, exist_ok=True)
    if not os.path.exists(AUTH_STATE_FILE):
        with open(AUTH_STATE_FILE, "w") as f:
            json.dump(_default_state(), f, indent=2)


def _load_state() -> Dict[str, Any]:
    _ensure_storage()
    with open(AUTH_STATE_FILE, "r") as f:
        return json.load(f)


def _save_state(state: Dict[str, Any]):
    _ensure_storage()
    with open(AUTH_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# -----------------------------
# Helpers
# -----------------------------


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _base32_secret() -> str:
    # 20 random bytes, base32 encoded without padding
    return base64.b32encode(os.urandom(20)).decode("utf-8").replace("=", "")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret + padding)
    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (int.from_bytes(h[offset: offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1, interval: int = 30, digits: int = 6) -> bool:
    counter = int(time.time() / interval)
    for delta in range(-window, window + 1):
        if _hotp(secret, counter + delta, digits) == str(code).zfill(digits):
            return True
    return False


# -----------------------------
# User and session management
# -----------------------------


def _deserialize_user(data: Dict[str, Any]) -> User:
    return User(
        id=data["id"],
        username=data["username"],
        email=data["email"],
        oidc_issuer=data.get("oidc_issuer"),
        oidc_subject=data.get("oidc_subject"),
        attributes=data.get("attributes", {}),
        mfa_factors=[MfaFactor(**factor) for factor in data.get("mfa_factors", [])],
    )


def _serialize_user(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "oidc_issuer": user.oidc_issuer,
        "oidc_subject": user.oidc_subject,
        "attributes": user.attributes,
        "mfa_factors": [factor.__dict__ for factor in user.mfa_factors],
    }


def _deserialize_session(data: Dict[str, Any]) -> Session:
    return Session(**data)


# -----------------------------
# Public API
# -----------------------------


def map_oidc_claims_to_user(claims: Dict[str, Any]) -> Tuple[User, Session]:
    """Map OIDC claims to an internal user record and create a session."""

    state = _load_state()
    issuer = claims.get("iss")
    subject = claims.get("sub")
    email = claims.get("email") or claims.get("preferred_username")
    username = claims.get("preferred_username") or (email.split("@")[0] if email else "user")

    users = [_deserialize_user(u) for u in state.get("users", [])]
    user = next((u for u in users if u.oidc_issuer == issuer and u.oidc_subject == subject), None)
    if not user and email:
        user = next((u for u in users if u.email == email), None)

    if not user:
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email or "unknown@example.com",
            oidc_issuer=issuer,
            oidc_subject=subject,
            attributes=claims,
            mfa_factors=[],
        )
        users.append(user)
    else:
        user.attributes.update(claims)

    session = create_session_for_user(user.id, claims.get("device_id"), claims.get("user_agent"))

    state["users"] = [_serialize_user(u) for u in users]
    _save_state(state)

    return user, session


def create_session_for_user(user_id: str, device_id: Optional[str], user_agent: Optional[str]) -> Session:
    state = _load_state()
    sessions = [_deserialize_session(s) for s in state.get("sessions", [])]
    session = Session(
        id=str(uuid.uuid4()),
        user_id=user_id,
        device_id=device_id or str(uuid.uuid4()),
        user_agent=user_agent,
        created_at=_now_iso(),
        last_active_at=_now_iso(),
        revoked=False,
    )
    sessions.append(session)
    state["sessions"] = [s.to_dict() for s in sessions]
    _save_state(state)
    return session


def list_sessions(user_id: str) -> List[Session]:
    state = _load_state()
    return [
        _deserialize_session(s) for s in state.get("sessions", []) if s.get("user_id") == user_id
    ]


def revoke_session(user_id: str, session_id: str) -> Session:
    state = _load_state()
    sessions = [_deserialize_session(s) for s in state.get("sessions", [])]
    session = next((s for s in sessions if s.id == session_id and s.user_id == user_id), None)
    if not session:
        raise ValueError("Session not found")
    session.revoked = True
    session.last_active_at = _now_iso()
    state["sessions"] = [s.to_dict() for s in sessions]
    _save_state(state)
    return session


def revoke_all_sessions(user_id: str) -> List[Session]:
    state = _load_state()
    sessions = [_deserialize_session(s) for s in state.get("sessions", [])]
    for session in sessions:
        if session.user_id == user_id:
            session.revoked = True
            session.last_active_at = _now_iso()
    state["sessions"] = [s.to_dict() for s in sessions]
    _save_state(state)
    return [s for s in sessions if s.user_id == user_id]


# -----------------------------
# MFA management
# -----------------------------


def enroll_totp(user_id: str, label: str) -> Tuple[MfaFactor, str]:
    state = _load_state()
    users = [_deserialize_user(u) for u in state.get("users", [])]
    user = next((u for u in users if u.id == user_id), None)
    if not user:
        raise ValueError("User not found")

    secret = _base32_secret()
    factor = MfaFactor(
        id=str(uuid.uuid4()),
        type="totp",
        label=label,
        created_at=_now_iso(),
        secret=secret,
        verified=False,
    )
    user.mfa_factors.append(factor)

    state["users"] = [_serialize_user(u) for u in users]
    _save_state(state)

    otpauth_uri = f"otpauth://totp/LLMCouncil:{user.email}?secret={secret}&issuer=LLMCouncil&digits=6&period=30"
    return factor, otpauth_uri


def verify_totp_factor(user_id: str, factor_id: str, code: str) -> bool:
    state = _load_state()
    users = [_deserialize_user(u) for u in state.get("users", [])]
    user = next((u for u in users if u.id == user_id), None)
    if not user:
        raise ValueError("User not found")

    factor = next((f for f in user.mfa_factors if f.id == factor_id and f.type == "totp"), None)
    if not factor or not factor.secret:
        raise ValueError("TOTP factor not found")

    if verify_totp(factor.secret, code):
        factor.verified = True
        factor.last_verified_at = _now_iso()
        state["users"] = [_serialize_user(u) for u in users]
        _save_state(state)
        return True

    return False


def enroll_webauthn_hook(user_id: str, label: str) -> MfaFactor:
    state = _load_state()
    users = [_deserialize_user(u) for u in state.get("users", [])]
    user = next((u for u in users if u.id == user_id), None)
    if not user:
        raise ValueError("User not found")

    challenge = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    factor = MfaFactor(
        id=str(uuid.uuid4()),
        type="webauthn",
        label=label,
        created_at=_now_iso(),
        verified=False,
        challenge=challenge,
    )
    user.mfa_factors.append(factor)

    state["users"] = [_serialize_user(u) for u in users]
    _save_state(state)
    return factor


def verify_webauthn_hook(user_id: str, factor_id: str, assertion: str) -> bool:
    state = _load_state()
    users = [_deserialize_user(u) for u in state.get("users", [])]
    user = next((u for u in users if u.id == user_id), None)
    if not user:
        raise ValueError("User not found")

    factor = next((f for f in user.mfa_factors if f.id == factor_id and f.type == "webauthn"), None)
    if not factor:
        raise ValueError("WebAuthn factor not found")

    if assertion:
        factor.verified = True
        factor.last_verified_at = _now_iso()
        factor.challenge = None
        state["users"] = [_serialize_user(u) for u in users]
        _save_state(state)
        return True

    return False


__all__ = [
    "User",
    "Session",
    "MfaFactor",
    "map_oidc_claims_to_user",
    "create_session_for_user",
    "list_sessions",
    "revoke_session",
    "revoke_all_sessions",
    "enroll_totp",
    "verify_totp_factor",
    "enroll_webauthn_hook",
    "verify_webauthn_hook",
]

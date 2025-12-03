"""Simple JSON storage for authentication data."""

import json
import os
from datetime import datetime
from hashlib import sha256
from typing import Dict, List, Optional

from .config import AUTH_DATA_FILE


def _ensure_data_file():
    """Ensure the auth data file exists with the proper schema."""
    os.makedirs(os.path.dirname(AUTH_DATA_FILE), exist_ok=True)
    if not os.path.exists(AUTH_DATA_FILE):
        with open(AUTH_DATA_FILE, "w") as f:
            json.dump({"users": [], "refresh_tokens": []}, f, indent=2)


def _load_data() -> Dict[str, List[Dict]]:
    _ensure_data_file()
    with open(AUTH_DATA_FILE, "r") as f:
        return json.load(f)


def _save_data(data: Dict[str, List[Dict]]):
    _ensure_data_file()
    with open(AUTH_DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


def hash_token(token: str) -> str:
    """Return a SHA-256 hash for safely storing refresh tokens."""
    return sha256(token.encode("utf-8")).hexdigest()


def get_user_by_email(email: str) -> Optional[Dict]:
    data = _load_data()
    for user in data.get("users", []):
        if user["email"].lower() == email.lower():
            return user
    return None


def get_user_by_id(user_id: str) -> Optional[Dict]:
    data = _load_data()
    for user in data.get("users", []):
        if user["id"] == user_id:
            return user
    return None


def add_user(user: Dict):
    data = _load_data()
    data.setdefault("users", []).append(user)
    _save_data(data)


def add_refresh_token(entry: Dict):
    data = _load_data()
    data.setdefault("refresh_tokens", []).append(entry)
    _save_data(data)


def get_refresh_token(jti: str) -> Optional[Dict]:
    data = _load_data()
    for token in data.get("refresh_tokens", []):
        if token["jti"] == jti:
            return token
    return None


def revoke_refresh_token(jti: str, *, replaced_by: Optional[str] = None, reason: str = "revoked"):
    data = _load_data()
    for token in data.get("refresh_tokens", []):
        if token["jti"] == jti:
            token["revoked"] = True
            token["revoked_reason"] = reason
            token["revoked_at"] = datetime.utcnow().isoformat()
            if replaced_by:
                token["replaced_by"] = replaced_by
            break
    _save_data(data)


def revoke_tokens_for_device(user_id: str, device_id: str):
    data = _load_data()
    changed = False
    for token in data.get("refresh_tokens", []):
        if token["user_id"] == user_id and token.get("device_id") == device_id and not token.get("revoked"):
            token["revoked"] = True
            token["revoked_reason"] = "logout"
            token["revoked_at"] = datetime.utcnow().isoformat()
            changed = True
    if changed:
        _save_data(data)


def replace_refresh_token(old_jti: str, new_entry: Dict):
    revoke_refresh_token(old_jti, replaced_by=new_entry["jti"], reason="rotated")
    add_refresh_token(new_entry)

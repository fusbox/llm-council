"""Authentication helpers for the LLM Council API."""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .config import AUTH_SECRET, DATA_DIR, DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME

logger = logging.getLogger(__name__)


@dataclass
class User:
    """Simple user record."""

    username: str
    email: str
    password_hash: str

    @classmethod
    def from_password(cls, username: str, email: str, password: str) -> "User":
        return cls(username=username, email=email, password_hash=hash_password(password))


class AuthStore:
    """JSON-backed storage for users and password reset tokens."""

    def __init__(self, path: str = "data/users.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, object] = {"users": [], "used_reset_tokens": []}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            logger.info("Initializing default user store at %s", self.path)
            self._data = {"users": [], "used_reset_tokens": []}
            self._bootstrap_default_user()
            self._save()
            return

        with self.path.open("r") as f:
            self._data = json.load(f)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w") as f:
            json.dump(self._data, f, indent=2)

    def _bootstrap_default_user(self) -> None:
        """Create a default admin user if none exists."""
        logger.warning(
            "Bootstrapping default admin user. Override via environment variables for production security."
        )
        admin = User.from_password(
            DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD
        )
        self._data["users"].append(admin.__dict__)

    def _find_user(self, username: str) -> Optional[Dict[str, str]]:
        return next((u for u in self._data["users"] if u["username"] == username), None)

    def _find_user_by_email(self, email: str) -> Optional[Dict[str, str]]:
        return next((u for u in self._data["users"] if u["email"].lower() == email.lower()), None)

    def authenticate(self, username: str, password: str) -> bool:
        user = self._find_user(username)
        if not user:
            return False
        return hmac.compare_digest(user["password_hash"], hash_password(password))

    def set_password(self, username: str, password: str) -> None:
        user = self._find_user(username)
        if not user:
            raise ValueError("User not found")
        user["password_hash"] = hash_password(password)
        self._save()

    def create_reset_token(self, email: str, ttl_seconds: int = 3600) -> Optional[str]:
        user = self._find_user_by_email(email)
        if not user:
            return None

        expires_at = int(time.time()) + ttl_seconds
        nonce = secrets.token_hex(8)
        payload = f"{user['username']}:{expires_at}:{nonce}"
        signature = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(payload.encode() + b"." + signature).decode()
        return token

    def token_used(self, token: str) -> bool:
        token_hash = hash_password(token)
        return token_hash in self._data.get("used_reset_tokens", [])

    def mark_token_used(self, token: str) -> None:
        token_hash = hash_password(token)
        if token_hash not in self._data.get("used_reset_tokens", []):
            self._data.setdefault("used_reset_tokens", []).append(token_hash)
            self._save()

    def validate_reset_token(self, token: str) -> Optional[str]:
        """Validate a signed reset token and return the username if valid."""
        if self.token_used(token):
            return None

        try:
            decoded = base64.urlsafe_b64decode(token.encode())
            payload_part, signature_part = decoded.rsplit(b".", 1)
        except Exception:
            logger.warning("Failed to decode reset token")
            return None

        expected_signature = hmac.new(AUTH_SECRET.encode(), payload_part, hashlib.sha256).digest()
        if not hmac.compare_digest(signature_part, expected_signature):
            logger.warning("Invalid reset token signature")
            return None

        try:
            payload = payload_part.decode()
            username, expires_at, _nonce = payload.split(":", 2)
            if int(expires_at) < int(time.time()):
                logger.info("Expired reset token for user %s", username)
                return None
        except Exception:
            logger.warning("Malformed reset token payload")
            return None

        return username


class RateLimiter:
    """In-memory rate limiter for login endpoints."""

    def __init__(self, max_attempts: int, window_seconds: int, block_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self.attempts: Dict[str, list[float]] = {}
        self.blocked_until: Dict[str, float] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        blocked_until = self.blocked_until.get(key)
        if blocked_until and now < blocked_until:
            return False

        window_start = now - self.window_seconds
        history = [t for t in self.attempts.get(key, []) if t > window_start]
        history.append(now)
        self.attempts[key] = history

        if len(history) > self.max_attempts:
            self.blocked_until[key] = now + self.block_seconds
            logger.warning("Rate limit exceeded for %s", key)
            return False

        return True


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


class Notifier:
    """Simple notifier abstraction for password reset messages."""

    def __init__(self, mode: str = "log"):
        self.mode = mode

    def send_password_reset(self, email: str, token: str) -> None:
        if self.mode == "log":
            logger.info("Sending password reset token", extra={"email": email, "token": token})
        else:
            logger.warning(
                "Notifier mode '%s' is not implemented. Token not delivered.",
                self.mode,
            )


# Initialize a shared auth store using the configured data directory
AUTH_STORE = AuthStore(path=os.path.join(DATA_DIR, "users.json"))


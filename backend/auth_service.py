"""Authentication service for handling users and tokens."""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

import bcrypt
from fastapi import HTTPException, status
from jose import JWTError, jwt

from . import auth_storage
from .config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_SECRET,
    REFRESH_TOKEN_EXPIRE_DAYS,
)


class AuthService:
    """Business logic for authentication workflows."""

    def _hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def _verify_password(self, password: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except ValueError:
            return False

    def _create_jwt(
        self, subject: str, token_type: str, expires_delta: timedelta, extra: Dict | None = None
    ) -> Tuple[str, Dict[str, str]]:
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        payload = {
            "sub": subject,
            "type": token_type,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int((now + expires_delta).timestamp()),
        }
        if extra:
            payload.update(extra)
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return token, payload

    def _validate_refresh_token(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token type")

        jti = payload.get("jti")
        token_record = auth_storage.get_refresh_token(jti)
        if not token_record:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown refresh token")

        if token_record.get("revoked"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

        if token_record.get("hashed") != auth_storage.hash_token(token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token mismatch")

        expires_at = datetime.fromisoformat(token_record["expires_at"])
        if expires_at < datetime.utcnow():
            auth_storage.revoke_refresh_token(jti, reason="expired")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

        return payload

    def sign_up(self, email: str, password: str, device_id: str) -> Dict:
        if auth_storage.get_user_by_email(email):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

        user_id = str(uuid.uuid4())
        user = {
            "id": user_id,
            "email": email,
            "password_hash": self._hash_password(password),
            "created_at": datetime.utcnow().isoformat(),
        }
        auth_storage.add_user(user)
        tokens = self._issue_tokens(user_id, email, device_id)
        return tokens["response"]

    def login(self, email: str, password: str, device_id: str) -> Dict:
        user = auth_storage.get_user_by_email(email)
        if not user or not self._verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        # Revoke existing tokens for this device
        auth_storage.revoke_tokens_for_device(user["id"], device_id)
        tokens = self._issue_tokens(user["id"], user["email"], device_id)
        return tokens["response"]

    def logout(self, refresh_token: str):
        payload = self._validate_refresh_token(refresh_token)
        auth_storage.revoke_refresh_token(payload["jti"], reason="logout")

    def refresh(self, refresh_token: str) -> Dict:
        payload = self._validate_refresh_token(refresh_token)
        user = auth_storage.get_user_by_id(payload["sub"])
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        new_tokens = self._issue_tokens(
            user["id"], user["email"], payload.get("device_id", "unknown"), persist_refresh=False
        )
        auth_storage.replace_refresh_token(payload["jti"], new_tokens["refresh_token_record"])
        return new_tokens["response"]

    def verify_access_token(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")

        if payload.get("type") != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        return payload

    def _issue_tokens(self, user_id: str, email: str, device_id: str, *, persist_refresh: bool = True) -> Dict:
        access_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        access_token, access_payload = self._create_jwt(
            user_id, "access", access_expires, {"email": email}
        )
        refresh_token, refresh_payload = self._create_jwt(
            user_id, "refresh", refresh_expires, {"device_id": device_id, "email": email}
        )

        refresh_record = {
            "jti": refresh_payload["jti"],
            "hashed": auth_storage.hash_token(refresh_token),
            "user_id": user_id,
            "device_id": device_id,
            "issued_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + refresh_expires).isoformat(),
            "revoked": False,
        }

        if persist_refresh:
            auth_storage.add_refresh_token(refresh_record)

        response = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(access_expires.total_seconds()),
            "user": {"id": user_id, "email": email},
        }

        return {"response": response, "refresh_token_record": refresh_record}

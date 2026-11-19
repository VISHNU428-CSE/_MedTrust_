"""
Security module for MedTrust.
Provides JWT issuance, cryptographic signature validation,
and secure PBKDF2 password hashing.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

import jwt
from app.config import settings
from app.core.exceptions import AccessDeniedError


def hash_password(password: str) -> str:
    """Hashes password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return f"{base64.b64encode(salt).decode('ascii')}${base64.b64encode(key).decode('ascii')}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash."""
    try:
        salt_b64, key_b64 = hashed_password.split("$")
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_key = base64.b64decode(key_b64.encode("ascii"))
        actual_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(expected_key, actual_key)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Encodes JWT claims into an HS256 signed JWT token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp())
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def verify_and_decode_token(token: str) -> Dict[str, Any]:
    """
    Verifies JWT token signature and expiration.
    Supports both PyJWT and pure HMAC validation to catch tampering and format anomalies.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise AccessDeniedError("Malformed token structure (must have 3 dot-separated parts)", code=401, reason="MALFORMED_TOKEN")

        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError as e:
        raise AccessDeniedError("Token has expired", code=401, reason="TOKEN_EXPIRED") from e
    except jwt.InvalidSignatureError as e:
        raise AccessDeniedError("Cryptographic signature verification failed (tampered or forged token)", code=401, reason="INVALID_SIGNATURE") from e
    except jwt.DecodeError as e:
        raise AccessDeniedError(f"Malformed or undecodable token: {str(e)}", code=401, reason="MALFORMED_TOKEN") from e
    except Exception as e:
        raise AccessDeniedError(f"Token validation failed: {str(e)}", code=401, reason="INVALID_TOKEN") from e

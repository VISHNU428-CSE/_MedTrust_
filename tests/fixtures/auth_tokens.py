"""
Authentication & JWT Fixtures for MedTrust Security Review.

Provides pure-Python cryptographic JWT generation (HMAC-SHA256)
to simulate and test authorization, token tampering, expiration, and RBAC roles.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Dict, Any, Tuple

DEFAULT_SECRET_KEY = "medtrust-test-secret-key-do-not-use-in-production"
TAMPERED_SECRET_KEY = "attacker-forged-secret-key-invalid"


def base64url_encode(data: bytes) -> str:
    """Encode bytes into base64url string without trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> bytes:
    """Decode base64url string with padding restoration."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data.encode("ascii"))


def create_jwt(payload: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY) -> str:
    """Creates a standard HS256 signed JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header, sort_keys=True).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_and_decode_jwt(token: str, secret_key: str = DEFAULT_SECRET_KEY) -> Tuple[bool, Dict[str, Any], str]:
    """
    Verifies JWT token signature and expiration.
    Returns: (is_valid, payload, error_message)
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, {}, "Malformed token structure (must have 3 dot-separated parts)"

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = base64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, {}, "Cryptographic signature verification failed (tampered or forged token)"

        payload_bytes = base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Expiration check
        exp = payload.get("exp")
        if exp is not None and time.time() > exp:
            return False, payload, "Token has expired"

        return True, payload, ""
    except Exception as e:
        return False, {}, f"Invalid token encoding: {str(e)}"


def get_patient_token(patient_id: str = "SYNTH-PAT-001", ttl_seconds: int = 3600) -> str:
    """Generate a valid JWT token for a synthetic patient."""
    now = int(time.time())
    payload = {
        "sub": patient_id,
        "role": "PATIENT",
        "name": "Synthetic Patient Alice",
        "iat": now,
        "exp": now + ttl_seconds
    }
    return create_jwt(payload)


def get_doctor_token(doctor_id: str = "SYNTH-DOC-101", ttl_seconds: int = 3600) -> str:
    """Generate a valid JWT token for a synthetic doctor."""
    now = int(time.time())
    payload = {
        "sub": doctor_id,
        "role": "DOCTOR",
        "license_id": "MED-SYNTH-9941",
        "iat": now,
        "exp": now + ttl_seconds
    }
    return create_jwt(payload)


def get_expired_token(user_id: str = "SYNTH-PAT-001", role: str = "PATIENT") -> str:
    """Generate an expired JWT token (expired 1 hour ago)."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now - 7200,
        "exp": now - 3600
    }
    return create_jwt(payload)


def get_tampered_signature_token(user_id: str = "SYNTH-PAT-001", role: str = "PATIENT") -> str:
    """Generate a token signed with an unauthorized secret key."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + 3600
    }
    return create_jwt(payload, secret_key=TAMPERED_SECRET_KEY)


def get_role_escalated_token(user_id: str = "SYNTH-PAT-001") -> str:
    """Simulate privilege escalation attempt: patient claiming ADMIN or DOCTOR role."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": "ADMIN",
        "iat": now,
        "exp": now + 3600
    }
    return create_jwt(payload)

"""RS256 JWT issuance/verification and JWKS serialization.

Refresh tokens and the `roles` claim land in a follow-up (see auth-service
issue tracking the "richer features" pass) — this is deliberately just the
core sign/verify/JWKS loop.
"""

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from jose import jwt, JWTError

from .keys import get_signing_keys
from ..config import get_settings


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    data = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    settings = get_settings()
    keys = get_signing_keys()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload,
        keys.private_pem,
        algorithm="RS256",
        headers={"kid": keys.kid},
    )


def verify_access_token(token: str) -> dict[str, Any]:
    keys = get_signing_keys()
    try:
        return jwt.decode(token, keys.public_pem, algorithms=["RS256"])
    except JWTError as e:
        raise ValueError("Invalid token") from e


def get_jwks() -> dict[str, Any]:
    keys = get_signing_keys()
    public_key = serialization.load_pem_public_key(keys.public_pem)
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": keys.kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }

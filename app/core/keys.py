"""RSA keypair used to sign/verify JWTs.

Generated once on first startup and persisted to disk (KEYS_DIR, expected to
be a mounted volume in Docker) — regenerating it on every restart would
instantly invalidate every previously-issued token. A stable `kid` is
generated alongside it so JWKS-based key rotation is possible later without
a redesign, even though rotation itself isn't implemented yet.
"""

import hashlib
import os
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..config import get_settings


class SigningKeys:
    def __init__(self, private_pem: bytes, public_pem: bytes, kid: str):
        self.private_pem = private_pem
        self.public_pem = public_pem
        self.kid = kid


def _generate_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _kid_from_public_key(public_pem: bytes) -> str:
    return hashlib.sha256(public_pem).hexdigest()[:16]


@lru_cache
def get_signing_keys() -> SigningKeys:
    settings = get_settings()
    keys_dir = settings.keys_dir
    os.makedirs(keys_dir, exist_ok=True)

    private_path = os.path.join(keys_dir, "private_key.pem")
    public_path = os.path.join(keys_dir, "public_key.pem")

    if os.path.exists(private_path) and os.path.exists(public_path):
        with open(private_path, "rb") as f:
            private_pem = f.read()
        with open(public_path, "rb") as f:
            public_pem = f.read()
    else:
        private_pem, public_pem = _generate_keypair()
        with open(private_path, "wb") as f:
            f.write(private_pem)
        os.chmod(private_path, 0o600)
        with open(public_path, "wb") as f:
            f.write(public_pem)

    return SigningKeys(private_pem, public_pem, _kid_from_public_key(public_pem))

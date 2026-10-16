from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings


@lru_cache
def _fernet() -> Fernet:
    key = get_settings().secrets_encryption_key
    if not key:
        raise RuntimeError(
            "SECRETS_ENCRYPTION_KEY is not set — required to store/read any "
            "user secret (e.g. an OpenRouter API key). Generate one with: "
            'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    return Fernet(key.encode())


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        # SECRETS_ENCRYPTION_KEY was rotated/lost, or the stored value predates
        # encryption — surface as "not set" rather than crashing the caller.
        raise ValueError("SECRET_UNDECRYPTABLE")

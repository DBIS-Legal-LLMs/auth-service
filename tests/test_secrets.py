"""encrypt_secret/decrypt_secret round-trip (auth-service#8 follow-up)."""

import pytest
from cryptography.fernet import Fernet

from app.core.secrets import encrypt_secret, decrypt_secret


def test_round_trip():
    plaintext = "sk-or-v1-abc123"
    ciphertext = encrypt_secret(plaintext)

    assert ciphertext != plaintext
    assert decrypt_secret(ciphertext) == plaintext


def test_ciphertext_is_not_deterministic():
    # Fernet includes a random IV/timestamp — same plaintext, different
    # ciphertext each time. Not load-bearing for correctness, but a
    # regression here would mean encryption silently stopped happening.
    a = encrypt_secret("sk-or-v1-abc123")
    b = encrypt_secret("sk-or-v1-abc123")
    assert a != b


def test_garbage_ciphertext_raises_rather_than_returning_garbage():
    with pytest.raises(ValueError, match="SECRET_UNDECRYPTABLE"):
        decrypt_secret("not-a-real-fernet-token")


def test_a_value_encrypted_under_a_different_key_is_undecryptable():
    other_key = Fernet.generate_key()
    ciphertext = Fernet(other_key).encrypt(b"sk-or-v1-abc123").decode()

    with pytest.raises(ValueError, match="SECRET_UNDECRYPTABLE"):
        decrypt_secret(ciphertext)

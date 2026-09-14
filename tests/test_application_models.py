"""Validation rules for the per-application role registry (auth-service#5).

Pure-model tests — no DB, no app import beyond pydantic. Run with `pytest`.
"""

import pytest
from pydantic import ValidationError

from app.models.application_models import ApplicationCreate

GRIPL_ROLES = [
    {"key": "admin", "label": "Admin"},
    {"key": "dpo", "label": "Data Protection Officer"},
    {"key": "researcher", "label": "Researcher"},
    {"key": "end-user", "label": "End User"},
]


def _app(**overrides):
    payload = {
        "_id": "gripl",
        "display_name": "GRIPL",
        "roles": GRIPL_ROLES,
        "default_role": "end-user",
    }
    payload.update(overrides)
    return ApplicationCreate(**payload)


def test_valid_application_registers():
    app = _app()
    assert app.id == "gripl"
    assert [r.key for r in app.roles] == ["admin", "dpo", "researcher", "end-user"]
    assert app.default_role == "end-user"


def test_every_app_must_define_an_admin_role():
    with pytest.raises(ValidationError, match="APP_MISSING_ADMIN_ROLE"):
        _app(roles=[{"key": "user", "label": "User"}], default_role="user")


def test_default_role_must_be_one_of_the_defined_roles():
    with pytest.raises(ValidationError, match="APP_DEFAULT_ROLE_UNKNOWN"):
        _app(default_role="ghost")


def test_roles_cannot_be_empty():
    with pytest.raises(ValidationError, match="APP_NO_ROLES"):
        _app(roles=[], default_role="admin")


def test_duplicate_role_keys_rejected():
    with pytest.raises(ValidationError, match="APP_DUPLICATE_ROLE_KEYS"):
        _app(roles=[
            {"key": "admin", "label": "Admin"},
            {"key": "admin", "label": "Administrator"},
        ], default_role="admin")


@pytest.mark.parametrize("bad_key", ["GRIPL", "gr ipl", "-gripl", "gripl-", "a", "x" * 60, "grïpl"])
def test_app_key_must_be_claim_safe(bad_key):
    with pytest.raises(ValidationError, match="APP_KEY_INVALID"):
        _app(_id=bad_key)


@pytest.mark.parametrize("ok_key", ["gripl", "ragulate", "dbis-tool-2", "ab"])
def test_reasonable_app_keys_accepted(ok_key):
    assert _app(_id=ok_key).id == ok_key


def test_ragulate_shape_from_the_issue():
    app = ApplicationCreate(
        _id="ragulate",
        display_name="RAGulate",
        roles=[{"key": "admin", "label": "Admin"}, {"key": "user", "label": "User"}],
        default_role="user",
    )
    assert app.default_role == "user"

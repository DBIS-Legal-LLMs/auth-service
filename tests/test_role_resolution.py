"""app_roles resolution at token-mint time (auth-service#6)."""

from datetime import datetime, timezone

from app.models.application_models import ApplicationInDB
from app.models.user_models import UserInDB
from app.services.role_resolution import resolve_app_roles, resolve_role

GRIPL = ApplicationInDB(
    _id="gripl",
    display_name="GRIPL",
    roles=[
        {"key": "admin", "label": "Admin"},
        {"key": "researcher", "label": "Researcher"},
        {"key": "end-user", "label": "End User"},
    ],
    default_role="end-user",
)
RAGULATE = ApplicationInDB(
    _id="ragulate",
    display_name="RAGulate",
    roles=[{"key": "admin", "label": "Admin"}, {"key": "user", "label": "User"}],
    default_role="user",
)


def _user(app_roles: dict[str, str] | None = None, *, is_superuser: bool = False) -> UserInDB:
    return UserInDB(
        _id="u1",
        email="u1@example.com",
        username="u1",
        password_hash="x",
        is_superuser=is_superuser,
        app_roles=app_roles or {},
        created_at=datetime.now(timezone.utc),
    )


def test_explicit_role_wins():
    user = _user({"gripl": "researcher"})
    assert resolve_role(user, GRIPL) == "researcher"


def test_missing_role_falls_back_to_app_default():
    user = _user({})
    assert resolve_role(user, GRIPL) == "end-user"
    assert resolve_role(user, RAGULATE) == "user"


def test_full_map_covers_every_registered_app():
    user = _user({"ragulate": "admin"})
    assert resolve_app_roles(user, [GRIPL, RAGULATE]) == {
        "gripl": "end-user",   # not assigned -> GRIPL's default
        "ragulate": "admin",   # explicitly assigned
    }


def test_default_role_change_applies_without_touching_the_user():
    user = _user({})
    gripl_v2 = GRIPL.model_copy(update={"default_role": "researcher"})
    assert resolve_role(user, gripl_v2) == "researcher"


def test_no_registered_apps_yields_empty_map():
    assert resolve_app_roles(_user({"gripl": "admin"}), []) == {}


# ----- global superuser tier (auth-service#7) -----

def test_superuser_resolves_to_admin_for_every_app():
    user = _user(is_superuser=True)
    assert resolve_app_roles(user, [GRIPL, RAGULATE]) == {"gripl": "admin", "ragulate": "admin"}


def test_superuser_override_beats_a_lower_explicit_role():
    user = _user({"gripl": "researcher"}, is_superuser=True)
    assert resolve_role(user, GRIPL) == "admin"


def test_non_superuser_is_unaffected():
    user = _user({"gripl": "researcher"}, is_superuser=False)
    assert resolve_role(user, GRIPL) == "researcher"

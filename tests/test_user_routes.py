"""PUT /users/{id}/roles/{app_id} — the per-app role-edit endpoint and its
global-superuser guard (auth-service#7).

Services are faked and injected via dependency_overrides; no DB, no real auth.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.deps import get_application_service, get_current_user, get_user_service
from app.core.security import hash_password
from app.main import app
from app.models.application_models import ApplicationInDB
from app.models.user_models import UserInDB

PASSWORD = "Sup3rSecret!pw"
_PW_HASH = hash_password(PASSWORD)

GRIPL = ApplicationInDB(
    _id="gripl",
    display_name="GRIPL",
    roles=[
        {"key": "admin", "label": "Admin"},
        {"key": "researcher", "label": "Researcher"},
        {"key": "user", "label": "End User"},
    ],
    default_role="user",
)


def _user(uid: str, *, is_superuser: bool = False, app_roles: dict[str, str] | None = None) -> UserInDB:
    return UserInDB(
        _id=uid,
        email=f"{uid}@example.com",
        username=uid,
        password_hash=_PW_HASH,
        is_superuser=is_superuser,
        app_roles=app_roles or {},
        created_at=datetime.now(timezone.utc),
    )


class FakeUserService:
    def __init__(self, users: list[UserInDB]):
        self.by_id = {u.id: u for u in users}
        self.openrouter_keys: dict[str, str] = {}

    async def get_by_id(self, user_id: str):
        return self.by_id.get(user_id)

    async def get_openrouter_api_key(self, user_id: str):
        return self.openrouter_keys.get(user_id)

    async def set_openrouter_api_key(self, user_id: str, api_key: str | None):
        if api_key:
            self.openrouter_keys[user_id] = api_key
        else:
            self.openrouter_keys.pop(user_id, None)

    async def set_app_role(self, user_id: str, app_id: str, role: str):
        user = self.by_id[user_id]
        user.app_roles[app_id] = role
        return user

    async def count_superusers(self) -> int:
        return sum(1 for u in self.by_id.values() if u.is_superuser)

    async def set_superuser(self, user_id: str, value: bool):
        user = self.by_id[user_id]
        user.is_superuser = value
        return user

    async def delete_user(self, user_id: str) -> bool:
        return self.by_id.pop(user_id, None) is not None


class FakeApplicationService:
    def __init__(self, apps: list[ApplicationInDB]):
        self.by_id = {a.id: a for a in apps}

    async def get(self, app_id: str):
        return self.by_id.get(app_id)


def client_for(caller: UserInDB, users: list[UserInDB], apps: list[ApplicationInDB] | None = None) -> TestClient:
    user_service = FakeUserService(users)
    application_service = FakeApplicationService(apps if apps is not None else [GRIPL])
    app.dependency_overrides[get_current_user] = lambda: caller
    app.dependency_overrides[get_user_service] = lambda: user_service
    app.dependency_overrides[get_application_service] = lambda: application_service
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def test_app_admin_can_set_a_users_role():
    caller = _user("boss", app_roles={"gripl": "admin"})
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/roles/gripl", json={"role": "researcher"})

    assert resp.status_code == 200
    assert resp.json()["app_roles"]["gripl"] == "researcher"


def test_superuser_can_set_a_users_role_even_without_an_explicit_gripl_admin_role():
    caller = _user("root", is_superuser=True)
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/roles/gripl", json={"role": "researcher"})

    assert resp.status_code == 200


def test_non_admin_caller_is_forbidden():
    caller = _user("nobody", app_roles={"gripl": "researcher"})
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/roles/gripl", json={"role": "admin"})

    assert resp.status_code == 403


def test_target_superuser_role_is_not_editable():
    caller = _user("boss", app_roles={"gripl": "admin"})
    target = _user("root", is_superuser=True)
    client = client_for(caller, [caller, target])

    resp = client.put("/users/root/roles/gripl", json={"role": "researcher"})

    assert resp.status_code == 409
    assert "superuser" in resp.json()["detail"]


def test_unknown_application_is_404():
    caller = _user("root", is_superuser=True)
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/roles/nope", json={"role": "admin"})

    assert resp.status_code == 404


def test_role_not_in_the_apps_vocabulary_is_400():
    caller = _user("root", is_superuser=True)
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/roles/gripl", json={"role": "wizard"})

    assert resp.status_code == 400


def test_unknown_target_user_is_404():
    caller = _user("root", is_superuser=True)
    client = client_for(caller, [caller])

    resp = client.put("/users/ghost/roles/gripl", json={"role": "researcher"})

    assert resp.status_code == 404


# ----- PUT /users/{id}/superuser + DELETE /users/me (auth-service#8) -----

def test_superuser_can_grant_the_tier_with_correct_password():
    caller = _user("root", is_superuser=True)
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/superuser", json={"is_superuser": True, "current_password": PASSWORD})

    assert resp.status_code == 200
    assert resp.json()["is_superuser"] is True


def test_non_superuser_cannot_reach_the_superuser_endpoint():
    caller = _user("boss", app_roles={"gripl": "admin"})
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/superuser", json={"is_superuser": True, "current_password": PASSWORD})

    assert resp.status_code == 403


def test_wrong_password_blocks_the_grant():
    caller = _user("root", is_superuser=True)
    target = _user("dave")
    client = client_for(caller, [caller, target])

    resp = client.put("/users/dave/superuser", json={"is_superuser": True, "current_password": "wrong"})

    assert resp.status_code == 403
    assert "reauthentication" in resp.json()["detail"].lower()


def test_cannot_demote_the_last_remaining_superuser():
    root = _user("root", is_superuser=True)
    client = client_for(root, [root])

    resp = client.put("/users/root/superuser", json={"is_superuser": False, "current_password": PASSWORD})

    assert resp.status_code == 409


def test_can_demote_a_superuser_when_another_remains():
    root = _user("root", is_superuser=True)
    other = _user("other", is_superuser=True)
    client = client_for(root, [root, other])

    resp = client.put("/users/other/superuser", json={"is_superuser": False, "current_password": PASSWORD})

    assert resp.status_code == 200
    assert resp.json()["is_superuser"] is False


def test_delete_own_account_succeeds_with_password():
    caller = _user("dave")
    client = client_for(caller, [caller])

    resp = client.request("DELETE", "/users/me", json={"current_password": PASSWORD})

    assert resp.status_code == 204


def test_delete_own_account_needs_the_right_password():
    caller = _user("dave")
    client = client_for(caller, [caller])

    resp = client.request("DELETE", "/users/me", json={"current_password": "nope"})

    assert resp.status_code == 403


def test_last_superuser_cannot_delete_their_own_account():
    root = _user("root", is_superuser=True)
    client = client_for(root, [root])

    resp = client.request("DELETE", "/users/me", json={"current_password": PASSWORD})

    assert resp.status_code == 409


def test_superuser_can_delete_their_own_account_when_another_superuser_remains():
    root = _user("root", is_superuser=True)
    other = _user("other", is_superuser=True)
    client = client_for(root, [root, other])

    resp = client.request("DELETE", "/users/me", json={"current_password": PASSWORD})

    assert resp.status_code == 204


# ----- GET/PUT /users/me — OpenRouter API key (auth-service#8 follow-up) -----

def test_get_my_profile_reports_no_key_when_unset():
    caller = _user("dave")
    client = client_for(caller, [caller])

    resp = client.get("/users/me")

    assert resp.status_code == 200
    assert resp.json()["openrouter_api_key"] is None
    assert "password_hash" not in resp.json()


def test_can_set_my_openrouter_api_key():
    caller = _user("dave")
    client = client_for(caller, [caller])

    resp = client.put("/users/me", json={"openrouter_api_key": "sk-or-v1-abc123"})

    assert resp.status_code == 200
    assert resp.json()["openrouter_api_key"] == "sk-or-v1-abc123"

    resp = client.get("/users/me")
    assert resp.json()["openrouter_api_key"] == "sk-or-v1-abc123"


def test_setting_an_empty_key_clears_it():
    caller = _user("dave")
    client = client_for(caller, [caller])
    client.put("/users/me", json={"openrouter_api_key": "sk-or-v1-abc123"})

    resp = client.put("/users/me", json={"openrouter_api_key": "   "})

    assert resp.status_code == 200
    assert resp.json()["openrouter_api_key"] is None


def test_my_openrouter_api_key_is_never_returned_from_other_endpoints():
    caller = _user("dave", app_roles={"gripl": "admin"})
    target = _user("eve")
    client = client_for(caller, [caller, target])
    client.put("/users/me", json={"openrouter_api_key": "sk-or-v1-abc123"})

    # Every other user-echoing endpoint returns UserPublic, not UserProfile —
    # the key must never appear outside GET/PUT /users/me.
    resp = client.put("/users/eve/roles/gripl", json={"role": "researcher"})
    assert "openrouter_api_key" not in resp.json()

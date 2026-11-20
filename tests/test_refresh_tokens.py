"""Refresh tokens (auth-service#13): rotation, reuse detection, grace window, expiry, revocation, and the
/auth/login, /auth/refresh, /auth/logout contract.

The token service runs for real on an in-memory stand-in for the Mongo collection; users and applications
are faked and injected via dependency_overrides. No DB.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from app.core.deps import (
    get_application_service,
    get_current_user,
    get_refresh_token_service,
    get_user_service,
)
from app.core.security import hash_password
from app.main import app
from app.models.application_models import ApplicationInDB
from app.models.user_models import UserInDB
from app.services.refresh_token_service import REUSE_GRACE, RefreshTokenService, hash_token

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


class FakeCollection:
    """The subset of the async PyMongo collection API that RefreshTokenService uses."""

    def __init__(self):
        self.docs: list[dict] = []

    @staticmethod
    def _matches(doc: dict, query: dict) -> bool:
        for key, want in query.items():
            have = doc.get(key)
            if isinstance(want, dict):
                if "$gt" in want and not (have is not None and have > want["$gt"]):
                    return False
            elif have != want:
                return False
        return True

    async def insert_one(self, doc: dict):
        assert all(d["token_hash"] != doc["token_hash"] for d in self.docs), "unique index on token_hash"
        self.docs.append(dict(doc))

    async def find_one(self, query: dict):
        return next((dict(d) for d in self.docs if self._matches(d, query)), None)

    async def find_one_and_update(self, query: dict, update: dict):
        for d in self.docs:
            if self._matches(d, query):
                before = dict(d)
                d.update(update["$set"])
                return before
        return None

    async def update_many(self, query: dict, update: dict):
        for d in self.docs:
            if self._matches(d, query):
                d.update(update["$set"])

    async def delete_many(self, query: dict):
        self.docs[:] = [d for d in self.docs if not self._matches(d, query)]


class FakeDb:
    def __init__(self):
        self.collection = FakeCollection()

    def __getitem__(self, name: str):
        assert name == "refresh_tokens"
        return self.collection


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

    async def verify_user(self, login: str, password: str):
        user = next((u for u in self.by_id.values() if login in (u.username, u.email)), None)
        return user if user and password == PASSWORD else None

    async def get_by_id(self, user_id: str):
        return self.by_id.get(user_id)

    async def backfill_app_roles(self, user_id: str, roles: dict[str, str]):
        self.by_id[user_id].app_roles.update(roles)

    async def count_superusers(self) -> int:
        return sum(1 for u in self.by_id.values() if u.is_superuser)

    async def set_superuser(self, user_id: str, value: bool):
        self.by_id[user_id].is_superuser = value
        return self.by_id[user_id]

    async def delete_user(self, user_id: str) -> bool:
        return self.by_id.pop(user_id, None) is not None


class FakeApplicationService:
    async def list_applications(self):
        return [GRIPL]


@pytest.fixture
def db():
    return FakeDb()


@pytest.fixture
def service(db):
    return RefreshTokenService(db)


@pytest.fixture
def users():
    return FakeUserService([_user("alice"), _user("root", is_superuser=True), _user("bob")])


@pytest.fixture
def client(db, users):
    app.dependency_overrides[get_user_service] = lambda: users
    app.dependency_overrides[get_application_service] = lambda: FakeApplicationService()
    app.dependency_overrides[get_refresh_token_service] = lambda: RefreshTokenService(db)
    yield TestClient(app)
    app.dependency_overrides.clear()


def run(coro):
    return asyncio.run(coro)


def login(client, username="alice"):
    resp = client.post("/auth/login", data={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()


def refresh(client, token):
    return client.post("/auth/refresh", json={"refresh_token": token})


def claims(access_token: str) -> dict:
    return jose_jwt.get_unverified_claims(access_token)


# ----- the token service -----

def test_only_the_hash_is_stored(service, db):
    token = run(service.start_family("alice"))

    (doc,) = db.collection.docs
    assert doc["token_hash"] == hash_token(token) != token
    assert token not in str(doc)
    assert len(token) >= 40


def test_rotation_returns_a_new_token_of_the_same_family_and_spends_the_old_one(service, db):
    first = run(service.start_family("alice"))

    user_id, second = run(service.rotate(first))

    assert user_id == "alice" and second != first
    first_doc, second_doc = db.collection.docs
    assert first_doc["used_at"] is not None and second_doc["used_at"] is None
    assert first_doc["family_id"] == second_doc["family_id"]


def test_rotation_does_not_extend_the_absolute_lifetime(service, db):
    first = run(service.start_family("alice"))
    run(service.rotate(first))

    first_doc, second_doc = db.collection.docs
    assert second_doc["expires_at"] == first_doc["expires_at"]
    assert abs(first_doc["expires_at"] - first_doc["created_at"] - timedelta(days=30)) < timedelta(seconds=5)


def test_unknown_token_is_rejected(service):
    assert run(service.rotate("not-a-token")) is None


def test_expired_token_is_rejected(service, db):
    token = run(service.start_family("alice"))
    db.collection.docs[0]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert run(service.rotate(token)) is None


def test_reuse_inside_the_grace_window_gets_another_token_and_keeps_the_family_alive(service, db):
    first = run(service.start_family("alice"))
    _, second = run(service.rotate(first))

    # the same client sent the old token a second time a moment later
    again = run(service.rotate(first))

    assert again is not None and again[0] == "alice"
    third = again[1]
    assert len({first, second, third}) == 3
    assert all(d["revoked_at"] is None for d in db.collection.docs)
    assert run(service.rotate(second)) is not None
    assert run(service.rotate(third)) is not None


def test_reuse_after_the_grace_window_revokes_the_whole_family(service, db):
    first = run(service.start_family("alice"))
    _, second = run(service.rotate(first))
    db.collection.docs[0]["used_at"] -= REUSE_GRACE + timedelta(seconds=1)

    assert run(service.rotate(first)) is None

    # the legitimate newest token is dead as well: whoever holds a copy of the old one is cut off, and so is the
    # user, who logs in again
    assert run(service.rotate(second)) is None
    assert all(d["revoked_at"] is not None for d in db.collection.docs)


def test_reuse_revokes_only_its_own_family(service, db):
    mine = run(service.start_family("alice"))
    other_login = run(service.start_family("alice"))
    run(service.rotate(mine))
    db.collection.docs[0]["used_at"] -= REUSE_GRACE + timedelta(seconds=1)
    run(service.rotate(mine))

    assert run(service.rotate(other_login)) is not None


def test_revoke_family_of_ends_the_login_and_ignores_unknown_tokens(service):
    token = run(service.start_family("alice"))
    other = run(service.start_family("alice"))

    run(service.revoke_family_of("unknown"))
    run(service.revoke_family_of(token))
    run(service.revoke_family_of(token))

    assert run(service.rotate(token)) is None
    assert run(service.rotate(other)) is not None


def test_revoke_all_for_user_leaves_other_users_alone(service):
    a1 = run(service.start_family("alice"))
    a2 = run(service.start_family("alice"))
    b = run(service.start_family("bob"))

    run(service.revoke_all_for_user("alice"))

    assert run(service.rotate(a1)) is None and run(service.rotate(a2)) is None
    assert run(service.rotate(b)) is not None


# ----- the endpoints -----

def test_login_returns_the_refresh_token_and_keeps_the_old_fields(client):
    body = login(client)

    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 15 * 60
    assert body["refresh_token"] and body["refresh_token"] != body["access_token"]
    assert body["user"]["username"] == "alice"
    assert claims(body["access_token"])["app_roles"] == {"gripl": "user"}


def test_failed_login_issues_no_refresh_token(client, db):
    resp = client.post("/auth/login", data={"username": "alice", "password": "wrong"})

    assert resp.status_code == 400
    assert db.collection.docs == []


def test_refresh_returns_the_login_shape_with_a_new_refresh_token(client):
    first = login(client)

    resp = refresh(client, first["refresh_token"])

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == set(first)
    assert body["refresh_token"] != first["refresh_token"]
    assert body["expires_in"] == first["expires_in"]
    assert body["user"]["id"] == "alice"
    assert claims(body["access_token"])["sub"] == "alice"
    # and the new refresh token works in turn
    assert refresh(client, body["refresh_token"]).status_code == 200


def test_refresh_re_resolves_roles_without_a_new_login(client, users):
    first = login(client)
    assert claims(first["access_token"])["app_roles"] == {"gripl": "user"}

    users.by_id["alice"].app_roles["gripl"] = "researcher"
    body = refresh(client, first["refresh_token"]).json()

    assert claims(body["access_token"])["app_roles"] == {"gripl": "researcher"}
    assert body["user"]["app_roles"] == {"gripl": "researcher"}


def test_refresh_re_resolves_the_superuser_tier(client, users):
    first = login(client, "bob")
    assert claims(first["access_token"])["is_superuser"] is False

    users.by_id["bob"].is_superuser = True
    body = refresh(client, first["refresh_token"]).json()

    claims_after = claims(body["access_token"])
    assert claims_after["is_superuser"] is True and claims_after["app_roles"] == {"gripl": "admin"}


@pytest.mark.parametrize("token", ["unknown", "x" * 43])
def test_refresh_with_an_unknown_token_is_401(client, token):
    resp = refresh(client, token)

    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid refresh token"}


@pytest.mark.parametrize("payload", [{}, {"refresh_token": ""}, {"refresh_token": None}])
def test_refresh_without_a_token_is_422(client, payload):
    assert client.post("/auth/refresh", json=payload).status_code == 422


def test_refresh_reuse_after_the_grace_window_is_401_and_kills_the_session(client, db):
    first = login(client)
    second = refresh(client, first["refresh_token"]).json()
    db.collection.docs[0]["used_at"] -= REUSE_GRACE + timedelta(seconds=1)

    assert refresh(client, first["refresh_token"]).status_code == 401
    assert refresh(client, second["refresh_token"]).status_code == 401


def test_refresh_reuse_inside_the_grace_window_is_200(client):
    first = login(client)
    assert refresh(client, first["refresh_token"]).status_code == 200

    assert refresh(client, first["refresh_token"]).status_code == 200


def test_refresh_of_a_deleted_user_is_401_and_removes_their_tokens(client, users, db):
    first = login(client)
    users.by_id.pop("alice")

    assert refresh(client, first["refresh_token"]).status_code == 401
    assert db.collection.docs == []


def test_logout_revokes_the_session_and_is_idempotent(client):
    first = login(client)

    assert client.post("/auth/logout", json={"refresh_token": first["refresh_token"]}).status_code == 204
    assert client.post("/auth/logout", json={"refresh_token": first["refresh_token"]}).status_code == 204
    assert client.post("/auth/logout", json={"refresh_token": "unknown"}).status_code == 204
    assert refresh(client, first["refresh_token"]).status_code == 401


def test_logout_ends_only_that_login(client):
    laptop = login(client)
    phone = login(client)

    client.post("/auth/logout", json={"refresh_token": laptop["refresh_token"]})

    assert refresh(client, phone["refresh_token"]).status_code == 200


def test_logout_without_a_token_is_422(client):
    assert client.post("/auth/logout", json={}).status_code == 422


# ----- revocation by the user endpoints -----

def _as(caller_id, users, client):
    app.dependency_overrides[get_current_user] = lambda: users.by_id[caller_id]


def test_deleting_the_own_account_revokes_its_refresh_tokens(client, users, db):
    session = login(client)
    other = login(client, "bob")
    _as("alice", users, client)

    resp = client.request("DELETE", "/users/me", json={"current_password": PASSWORD})

    assert resp.status_code == 204
    assert all(d["user_id"] == "bob" for d in db.collection.docs)
    assert refresh(client, other["refresh_token"]).status_code == 200
    assert refresh(client, session["refresh_token"]).status_code == 401


def test_demoting_a_superuser_revokes_their_refresh_tokens(client, users):
    second_root = _user("root2", is_superuser=True)
    users.by_id["root2"] = second_root
    session = login(client, "root2")
    _as("root", users, client)

    resp = client.put("/users/root2/superuser", json={"is_superuser": False, "current_password": PASSWORD})

    assert resp.status_code == 200
    assert refresh(client, session["refresh_token"]).status_code == 401


def test_promoting_a_user_does_not_revoke_their_session(client, users):
    session = login(client, "bob")
    _as("root", users, client)

    resp = client.put("/users/bob/superuser", json={"is_superuser": True, "current_password": PASSWORD})

    assert resp.status_code == 200
    assert refresh(client, session["refresh_token"]).status_code == 200

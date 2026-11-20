"""Opaque, rotating refresh tokens (auth-service#13).

A refresh token is a random string handed to the client once. Only its SHA-256 hash is stored, so a
database leak does not leak usable sessions, and a token can be revoked (unlike a JWT).

Every login starts a *family*. Each use of a token (`rotate`) marks it used and issues a successor in the
same family. All tokens of a family expire at the same moment, `REFRESH_TOKEN_EXPIRE_DAYS` after the login
(absolute: rotating does not extend the session). Presenting a token that was already used means that
someone holds a copy: within a short grace window it is treated as two parallel requests of the same
client and answered with another successor; after it the whole family is revoked.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from pymongo.asynchronous.database import AsyncDatabase

from ..config import get_settings

REFRESH_TOKENS_COLLECTION = "refresh_tokens"

# A second request that arrives with a token that was just exchanged (two server actions refreshing at once)
# is not an attack; it gets a new token in the same family.
REUSE_GRACE = timedelta(seconds=10)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    # PyMongo returns naive datetimes (UTC) unless the client is tz-aware
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def ensure_indexes(db: AsyncDatabase) -> None:
    """Idempotent; called once when the application starts."""
    collection = db[REFRESH_TOKENS_COLLECTION]
    await collection.create_index("token_hash", unique=True)
    await collection.create_index("family_id")
    await collection.create_index("user_id")
    # MongoDB deletes the document when `expires_at` has passed (checked about once a minute)
    await collection.create_index("expires_at", expireAfterSeconds=0)


class RefreshTokenService:
    def __init__(self, db: AsyncDatabase):
        self._db = db

    @property
    def tokens(self):
        return self._db[REFRESH_TOKENS_COLLECTION]

    async def _store(self, user_id: str, family_id: str, expires_at: datetime) -> str:
        token = secrets.token_urlsafe(32)
        await self.tokens.insert_one(
            {
                "token_hash": hash_token(token),
                "user_id": user_id,
                "family_id": family_id,
                "created_at": datetime.now(timezone.utc),
                "expires_at": expires_at,
                "used_at": None,
                "revoked_at": None,
            }
        )
        return token

    async def start_family(self, user_id: str) -> str:
        """The first refresh token of a login."""
        lifetime = timedelta(days=get_settings().refresh_token_expire_days)
        return await self._store(user_id, uuid.uuid4().hex, datetime.now(timezone.utc) + lifetime)

    async def rotate(self, token: str) -> Optional[tuple[str, str]]:
        """Exchange a token for its successor; returns (user_id, new_token), or None if it is not valid.

        None covers: unknown, expired, revoked, and reused after the grace window (which also revokes the
        family).
        """
        now = datetime.now(timezone.utc)
        token_hash = hash_token(token)

        # atomic: of two concurrent requests with the same token exactly one gets here with a document
        doc = await self.tokens.find_one_and_update(
            {
                "token_hash": token_hash,
                "used_at": None,
                "revoked_at": None,
                "expires_at": {"$gt": now},
            },
            {"$set": {"used_at": now}},
        )
        if doc is None:
            doc = await self.tokens.find_one({"token_hash": token_hash})
            if doc is None or doc.get("revoked_at") is not None or _utc(doc["expires_at"]) <= now:
                return None
            if now - _utc(doc["used_at"]) > REUSE_GRACE:
                await self._revoke_family(doc["family_id"])
                return None

        new_token = await self._store(doc["user_id"], doc["family_id"], _utc(doc["expires_at"]))
        return doc["user_id"], new_token

    async def _revoke_family(self, family_id: str) -> None:
        await self.tokens.update_many(
            {"family_id": family_id, "revoked_at": None},
            {"$set": {"revoked_at": datetime.now(timezone.utc)}},
        )

    async def revoke_family_of(self, token: str) -> None:
        """Logout. Idempotent: an unknown token is ignored."""
        doc = await self.tokens.find_one({"token_hash": hash_token(token)})
        if doc is not None:
            await self._revoke_family(doc["family_id"])

    async def revoke_all_for_user(self, user_id: str) -> None:
        await self.tokens.delete_many({"user_id": user_id})

import random
import time
import asyncio
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from bson.errors import InvalidId
from pymongo.asynchronous.database import AsyncDatabase

from ..data import func
from ..models.application_models import ApplicationInDB
from ..models.user_models import UserCreate, UserInDB
from ..core.security import (
    hash_password,
    verify_password,
    validate_email_address,
    validate_password_policy,
)

USERS_COLLECTION = "users"


def _generate_random_username_base() -> str:
    parts: list[str] = []
    PREFIX_WORDS, SUFFIX_WORDS, NUMBER_CHARS = func.get_username_parts()

    if PREFIX_WORDS:
        parts.append(random.choice(PREFIX_WORDS))

    suffix_count = 1 if len(SUFFIX_WORDS) < 2 else random.randint(1, 2)
    for _ in range(suffix_count):
        if SUFFIX_WORDS:
            parts.append(random.choice(SUFFIX_WORDS))

    digit_count = random.randint(3, 5)
    digits = "".join(random.choice(NUMBER_CHARS) for _ in range(digit_count))

    return "".join(parts) + digits


class UserService:
    def __init__(self, db: AsyncDatabase):
        self._db = db

    @property
    def users(self):
        return self._db[USERS_COLLECTION]

    # ----- CREATE USER -----
    async def create_user(
        self, user_in: UserCreate, applications: list[ApplicationInDB] | None = None
    ) -> UserInDB:
        try:
            normalized_email = validate_email_address(user_in.email)
        except ValueError:
            raise ValueError("EMAIL_INVALID")

        existing = await self.get_by_email(normalized_email)
        if existing:
            raise ValueError("EMAIL_EXISTS")

        username = user_in.username
        if username:
            username_exists = await self.users.find_one({"username": username})
            if username_exists:
                raise ValueError("USERNAME_EXISTS")
        else:
            raise ValueError("USERNAME_EMPTY")

        pw_errors = validate_password_policy(user_in.password)
        if pw_errors:
            raise ValueError({"type": "PASSWORD_POLICY", "errors": pw_errors})

        password_hash = hash_password(user_in.password)

        # Snapshot each registered app's default role onto the user document at
        # creation time, so `app_roles` is always a readable record of what the
        # user actually has rather than something only resolved implicitly at
        # login (auth-service#6 follow-up). A superuser still resolves to
        # "admin" everywhere regardless of what's stored here.
        app_roles = {app.id: app.default_role for app in (applications or [])}

        doc = {
            "email": normalized_email,
            "full_name": user_in.full_name,
            "username": username,
            "password_hash": password_hash,
            "role": "user",
            "is_superuser": False,
            "preferred_llm_provider": None,
            "preferred_model": None,
            "openrouter_api_key": None,
            "app_roles": app_roles,
            "created_at": datetime.now(timezone.utc),
        }

        result = await self.users.insert_one(doc)
        doc["_id"] = str(result.inserted_id)
        return UserInDB(**doc)

    async def generate_unique_username(self) -> Optional[str]:
        start = time.monotonic()
        while True:
            candidate = _generate_random_username_base()
            existing = await self.users.find_one({"username": candidate})
            if not existing:
                return candidate
            if time.monotonic() - start > 15:
                return None
            await asyncio.sleep(0.01)

    # ----- GET USER -----
    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        doc = await self.users.find_one({"email": email})
        if not doc:
            return None
        doc["_id"] = str(doc["_id"])
        return UserInDB(**doc)

    async def get_by_id(self, user_id: str) -> Optional[UserInDB]:
        try:
            oid = ObjectId(user_id)
        except (InvalidId, TypeError):
            return None
        doc = await self.users.find_one({"_id": oid})
        if not doc:
            return None
        doc["_id"] = str(doc["_id"])
        return UserInDB(**doc)

    async def get_by_username(self, username: str) -> Optional[UserInDB]:
        doc = await self.users.find_one({"username": username})
        if not doc:
            return None
        doc["_id"] = str(doc["_id"])
        return UserInDB(**doc)

    # ----- SUPERUSER TIER -----
    async def count_superusers(self) -> int:
        return await self.users.count_documents({"is_superuser": True})

    async def set_superuser(self, user_id: str, value: bool) -> Optional[UserInDB]:
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_superuser": value}},
        )
        return await self.get_by_id(user_id)

    async def delete_user(self, user_id: str) -> bool:
        result = await self.users.delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0

    # ----- ROLES -----
    async def set_app_role(self, user_id: str, app_id: str, role: str) -> Optional[UserInDB]:
        """Set (or overwrite) the target user's explicit role for one app.

        Only touches `app_roles.<app_id>`. Superuser-target and caller-authz
        checks live in the route (auth-service#7) — this is the raw write.
        """
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {f"app_roles.{app_id}": role}},
        )
        return await self.get_by_id(user_id)

    async def backfill_app_roles(self, user_id: str, roles: dict[str, str]) -> Optional[UserInDB]:
        """Write explicit `app_roles` entries for apps the user doesn't have one for yet.

        Only ever adds missing keys (the caller is expected to have already
        filtered to `app.id not in user.app_roles`) — never overwrites an
        existing explicit assignment.
        """
        if not roles:
            return await self.get_by_id(user_id)
        await self.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {f"app_roles.{app_id}": role for app_id, role in roles.items()}},
        )
        return await self.get_by_id(user_id)

    # ----- VERIFY USER -----
    async def verify_user(self, login: str, password: str) -> Optional[UserInDB]:
        user_by_email = await self.get_by_email(login)
        user_by_username = await self.get_by_username(login)
        user = user_by_email if user_by_email else user_by_username
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

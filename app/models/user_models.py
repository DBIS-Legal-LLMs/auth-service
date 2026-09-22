from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None
    username: str


class UserCreate(UserBase):
    password: str = Field(min_length=8)


class UserInDB(UserBase):
    id: str | None = Field(default=None, alias="_id")
    password_hash: str
    # Global superuser tier (auth-service#7): resolves to "admin" for *every*
    # registered app at token-mint time, regardless of what `app_roles` holds.
    # Separate from `app_roles`, and not directly editable via the per-app
    # role endpoint (409s on a superuser target) — the login backfill is the
    # only path that ever writes "admin" into a superuser's `app_roles`, and
    # only for apps they have no entry for yet.
    is_superuser: bool = False
    openrouter_api_key: str | None = None
    # Per-consuming-app role, e.g. {"gripl": "user", "ragulate": "admin"}.
    # Not enforced here — each app interprets its own entry.
    app_roles: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        populate_by_name = True


class UserPublic(UserBase):
    id: str
    is_superuser: bool = False
    app_roles: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    @classmethod
    def from_user(cls, user: UserInDB) -> "UserPublic":
        return cls(
            id=str(user.id),
            email=user.email,
            full_name=user.full_name,
            username=user.username,
            is_superuser=user.is_superuser,
            app_roles=user.app_roles,
            created_at=user.created_at,
        )



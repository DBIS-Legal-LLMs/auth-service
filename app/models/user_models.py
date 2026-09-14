from datetime import datetime
from typing import Literal

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
    role: Literal["user", "admin"] = "user"
    # Global superuser tier (auth-service#7): resolves to "admin" for *every*
    # registered app at token-mint time. Separate from `app_roles` — never
    # written per-app, and not directly editable via the per-app role endpoint.
    is_superuser: bool = False
    preferred_llm_provider: str | None = None
    preferred_model: str | None = None
    openrouter_api_key: str | None = None
    # Per-consuming-app role, e.g. {"gripl": "user", "ragulate": "admin"}.
    # Not enforced here — each app interprets its own entry.
    app_roles: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        populate_by_name = True


class UserPublic(UserBase):
    id: str
    role: Literal["user", "admin"] = "user"
    is_superuser: bool = False
    preferred_llm_provider: str | None = None
    preferred_model: str | None = None
    app_roles: dict[str, str] = Field(default_factory=dict)
    created_at: datetime

    @classmethod
    def from_user(cls, user: UserInDB) -> "UserPublic":
        return cls(
            id=str(user.id),
            email=user.email,
            full_name=user.full_name,
            username=user.username,
            role=user.role,
            is_superuser=user.is_superuser,
            preferred_llm_provider=user.preferred_llm_provider,
            preferred_model=user.preferred_model,
            app_roles=user.app_roles,
            created_at=user.created_at,
        )



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
    preferred_llm_provider: str | None = None
    preferred_model: str | None = None
    app_roles: dict[str, str] = Field(default_factory=dict)
    created_at: datetime



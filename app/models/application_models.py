import re

from pydantic import BaseModel, Field, field_validator, model_validator

# Consuming-app keys are used as the Mongo `_id` and as JWT `app_roles` keys —
# keep them URL/claim-safe and stable.
APP_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$")

# Every registered app must define a role with this key: the global superuser
# tier (auth-service#7) resolves to it for every app, so it always has to exist.
ADMIN_ROLE_KEY = "admin"

# Every registered app must also define this role, and it is always the
# default for users with no explicit assignment — keeps the "no role yet"
# case named the same way across every consuming app, rather than each app
# picking its own key (GRIPL used to call it "end-user").
DEFAULT_ROLE_KEY = "user"


class RoleOption(BaseModel):
    """One selectable role in a consuming app's vocabulary."""

    key: str = Field(min_length=1, max_length=40)
    label: str = Field(min_length=1, max_length=80)


class ApplicationBase(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    roles: list[RoleOption]
    default_role: str = DEFAULT_ROLE_KEY

    @model_validator(mode="after")
    def _validate_roles(self) -> "ApplicationBase":
        keys = [role.key for role in self.roles]
        if not keys:
            raise ValueError("APP_NO_ROLES")
        if len(keys) != len(set(keys)):
            raise ValueError("APP_DUPLICATE_ROLE_KEYS")
        if ADMIN_ROLE_KEY not in keys:
            raise ValueError("APP_MISSING_ADMIN_ROLE")
        if DEFAULT_ROLE_KEY not in keys:
            raise ValueError("APP_MISSING_USER_ROLE")
        if self.default_role != DEFAULT_ROLE_KEY:
            raise ValueError("APP_DEFAULT_ROLE_MUST_BE_USER")
        return self


class ApplicationCreate(ApplicationBase):
    """Payload for registering an app (script / direct DB write — no HTTP CRUD)."""

    id: str = Field(alias="_id")

    class Config:
        populate_by_name = True

    @field_validator("id")
    @classmethod
    def _validate_key(cls, value: str) -> str:
        if not APP_KEY_PATTERN.fullmatch(value):
            raise ValueError("APP_KEY_INVALID")
        return value


class ApplicationInDB(ApplicationBase):
    id: str = Field(alias="_id")

    class Config:
        populate_by_name = True


class ApplicationPublic(ApplicationBase):
    id: str

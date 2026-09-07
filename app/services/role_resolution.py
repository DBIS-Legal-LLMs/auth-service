"""Resolve a user's effective per-application roles at token-mint time.

`auth-service` issues one shared token usable against every consuming app (not
audience-scoped), so every issued token carries the *full* resolved map:

    "app_roles": {"gripl": "researcher", "ragulate": "admin"}

Each consuming app reads its own key and ignores the rest — no extra round-trip
to find out "what's my role here".

Resolution is computed fresh every mint rather than written to the user
document, so changing an app's `default_role` later immediately applies to
everyone who was never explicitly assigned a role.
"""

from ..models.application_models import ApplicationInDB
from ..models.user_models import UserInDB


def resolve_role(user: UserInDB, app: ApplicationInDB) -> str:
    """The user's effective role for one app: their explicitly-assigned role,
    else the app's `default_role`.

    (auth-service#7 adds the global-superuser override here: a superuser
    resolves to ``"admin"`` for every app.)
    """
    return user.app_roles.get(app.id) or app.default_role


def resolve_app_roles(user: UserInDB, applications: list[ApplicationInDB]) -> dict[str, str]:
    """The full `{app_id: role}` map to embed in an issued token."""
    return {app.id: resolve_role(user, app) for app in applications}

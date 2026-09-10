from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ...core.deps import get_application_service, get_current_user, get_user_service
from ...models.user_models import UserInDB, UserPublic
from ...services.application_service import ApplicationService
from ...services.role_resolution import resolve_role
from ...services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


class RoleAssignment(BaseModel):
    role: str


@router.put("/{user_id}/roles/{app_id}", response_model=UserPublic)
async def set_user_app_role(
    user_id: str,
    app_id: str,
    assignment: RoleAssignment,
    caller: UserInDB = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
    application_service: ApplicationService = Depends(get_application_service),
):
    """Set a user's explicit role for one registered app.

    This is the per-app admin's role-edit endpoint (replacing direct Mongo
    edits). It:

    * requires the caller to be a **global superuser** or an **admin of this
      specific app** (their own resolved `app_roles[app_id]`);
    * refuses (409) if the *target* is a global superuser — a superuser's
      effective role is `"admin"` everywhere by definition (auth-service#7) and
      is not editable per-app by anyone, in any project. Managing the superuser
      tier itself is a separate, reauthenticated endpoint (auth-service#8).
    """
    app = await application_service.get(app_id)
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No application registered with id '{app_id}'",
        )

    valid_role_keys = sorted(role.key for role in app.roles)
    if assignment.role not in valid_role_keys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{assignment.role}' is not a role of application '{app_id}' (one of {valid_role_keys})",
        )

    caller_is_app_admin = caller.is_superuser or resolve_role(caller, app) == "admin"
    if not caller_is_app_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not an admin for application '{app_id}'",
        )

    target = await user_service.get_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user is a global superuser — role isn't directly editable",
        )

    updated = await user_service.set_app_role(user_id, app_id, assignment.role)
    return UserPublic.from_user(updated)

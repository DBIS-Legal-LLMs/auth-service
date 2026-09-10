from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel

from ...core.deps import get_application_service, get_current_user, get_user_service
from ...core.security import verify_password
from ...models.user_models import UserInDB, UserPublic
from ...services.application_service import ApplicationService
from ...services.role_resolution import resolve_role
from ...services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


class RoleAssignment(BaseModel):
    role: str


class SuperuserAssignment(BaseModel):
    is_superuser: bool
    current_password: str


class AccountDeletion(BaseModel):
    current_password: str


def _reauthenticate(caller: UserInDB, password: str) -> None:
    """Step-up check: the caller must re-supply their *current* password for the
    most consequential actions (auth-service#8) — holding a valid access token
    is not enough on its own. A stolen token alone must not be able to mint a
    superuser or delete an account."""
    if not verify_password(password, caller.password_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reauthentication failed",
        )


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


@router.put("/{user_id}/superuser", response_model=UserPublic)
async def set_superuser(
    user_id: str,
    body: SuperuserAssignment,
    caller: UserInDB = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Grant or revoke the global superuser tier on a user (auth-service#8).

    * Caller must already be a superuser (an app-scoped admin can never reach
      this; nobody can, before the first superuser is bootstrapped).
    * Caller must re-supply their own current password.
    * The system must always keep at least one superuser — revoking the flag
      from the last remaining superuser is refused (even by a different
      superuser), mirroring the self-deletion guard.
    """
    if not caller.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a global superuser can manage the superuser tier",
        )
    _reauthenticate(caller, body.current_password)

    target = await user_service.get_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.is_superuser and not body.is_superuser and await user_service.count_superusers() <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot demote the last remaining superuser",
        )

    updated = await user_service.set_superuser(user_id, body.is_superuser)
    return UserPublic.from_user(updated)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_own_account(
    body: AccountDeletion,
    caller: UserInDB = Depends(get_current_user),
    user_service: UserService = Depends(get_user_service),
):
    """Delete the caller's own account (auth-service#8).

    Requires password reauthentication. A superuser cannot delete their own
    account while they are the last remaining superuser — demote/replace first.
    """
    _reauthenticate(caller, body.current_password)

    if caller.is_superuser and await user_service.count_superusers() <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete your own account: you are the last remaining superuser",
        )

    await user_service.delete_user(str(caller.id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)

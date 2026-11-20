from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from ...config import get_settings
from ...models.user_models import UserCreate, UserInDB, UserPublic
from ...services.application_service import ApplicationService
from ...services.refresh_token_service import RefreshTokenService
from ...services.role_resolution import resolve_app_roles
from ...services.user_service import UserService
from ...core.jwt import create_access_token
from ...core.deps import get_application_service, get_refresh_token_service, get_user_service

router = APIRouter(prefix="/auth", tags=["auth"])


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


@router.get("/register/genuser")
async def generate_username(
    user_service: UserService = Depends(get_user_service),
):
    username = await user_service.generate_unique_username()
    return username


@router.post("/register", response_model=UserPublic)
async def register(
    user_in: UserCreate,
    user_service: UserService = Depends(get_user_service),
    application_service: ApplicationService = Depends(get_application_service),
):
    try:
        applications = await application_service.list_applications()
        user = await user_service.create_user(user_in, applications)
    except ValueError as e:
        error = e.args[0]

        if isinstance(error, dict) and error.get("type") == "PASSWORD_POLICY":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=error,
            )
        if error == "EMAIL_INVALID":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Email")
        if error == "EMAIL_EXISTS":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
        if error == "USERNAME_EXISTS":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Registration failed")

    return UserPublic.from_user(user)


async def _session_response(
    user: UserInDB,
    refresh_token: str,
    user_service: UserService,
    application_service: ApplicationService,
) -> dict:
    """The body of login and refresh: a freshly minted access token plus the refresh token.

    Roles are resolved at mint time, from the database as it is now — a role change therefore reaches the
    user at the next refresh, without a new login.
    """
    # Resolve the user's effective role for every registered app, fresh at mint
    # time, and embed the whole map — each consuming app reads its own key.
    applications = await application_service.list_applications()
    app_roles = resolve_app_roles(user, applications)

    # Backfill: any app the user has no *explicit* app_roles entry for yet
    # (registered before this user existed, or before the app itself was
    # registered) gets one written now, so the DB always reflects what a
    # user effectively has rather than relying on resolution-at-read-time.
    # Never overwrites an existing explicit assignment.
    missing_roles = {
        app.id: ("admin" if user.is_superuser else app.default_role)
        for app in applications
        if app.id not in user.app_roles
    }
    if missing_roles:
        await user_service.backfill_app_roles(str(user.id), missing_roles)

    token = create_access_token(
        subject=str(user.id),
        extra_claims={"app_roles": app_roles, "is_superuser": user.is_superuser},
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": get_settings().access_token_expire_minutes * 60,
        "refresh_token": refresh_token,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_superuser": user.is_superuser,
            "app_roles": app_roles,
            "created_at": user.created_at.isoformat(),
        },
    }


@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_service: UserService = Depends(get_user_service),
    application_service: ApplicationService = Depends(get_application_service),
    refresh_tokens: RefreshTokenService = Depends(get_refresh_token_service),
):
    user = await user_service.verify_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email/username or password",
        )

    refresh_token = await refresh_tokens.start_family(str(user.id))
    return await _session_response(user, refresh_token, user_service, application_service)


@router.post("/refresh")
async def refresh(
    body: RefreshRequest,
    user_service: UserService = Depends(get_user_service),
    application_service: ApplicationService = Depends(get_application_service),
    refresh_tokens: RefreshTokenService = Depends(get_refresh_token_service),
):
    """Exchange a refresh token for a new access token and a new refresh token (the old one is spent).

    401 for every kind of invalid token (unknown, expired, revoked, reused, owner deleted) so that the
    answer does not tell an attacker which one it was.
    """
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    rotated = await refresh_tokens.rotate(body.refresh_token)
    if rotated is None:
        raise invalid
    user_id, new_token = rotated

    user = await user_service.get_by_id(user_id)
    if user is None:
        await refresh_tokens.revoke_all_for_user(user_id)
        raise invalid
    return await _session_response(user, new_token, user_service, application_service)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: RefreshRequest,
    refresh_tokens: RefreshTokenService = Depends(get_refresh_token_service),
):
    """Revoke the session (every refresh token of this login). Unknown tokens are ignored."""
    await refresh_tokens.revoke_family_of(body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

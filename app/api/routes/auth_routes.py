from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from ...models.user_models import UserCreate, UserPublic
from ...services.application_service import ApplicationService
from ...services.role_resolution import resolve_app_roles
from ...services.user_service import UserService
from ...core.jwt import create_access_token
from ...core.deps import get_application_service, get_user_service

router = APIRouter(prefix="/auth", tags=["auth"])


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
):
    try:
        user = await user_service.create_user(user_in)
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

    return UserPublic(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        username=user.username,
        role=user.role,
        preferred_llm_provider=user.preferred_llm_provider,
        preferred_model=user.preferred_model,
        app_roles=user.app_roles,
        created_at=user.created_at,
    )


@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_service: UserService = Depends(get_user_service),
    application_service: ApplicationService = Depends(get_application_service),
):
    user = await user_service.verify_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email/username or password",
        )

    # Resolve the user's effective role for every registered app, fresh at mint
    # time, and embed the whole map — each consuming app reads its own key.
    applications = await application_service.list_applications()
    app_roles = resolve_app_roles(user, applications)

    token = create_access_token(subject=str(user.id), extra_claims={"app_roles": app_roles})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "preferred_llm_provider": user.preferred_llm_provider,
            "preferred_model": user.preferred_model,
            "app_roles": app_roles,
            "created_at": user.created_at.isoformat(),
        },
    }

import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pymongo.asynchronous.database import AsyncDatabase

from ..db.mongo import get_database
from ..services.application_service import ApplicationService
from ..services.refresh_token_service import RefreshTokenService
from ..services.user_service import UserService
from .jwt import verify_access_token
from ..models.user_models import UserInDB

logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    return get_database()


def get_user_service(db: AsyncDatabase = Depends(get_db)) -> UserService:
    return UserService(db)


def get_application_service(db: AsyncDatabase = Depends(get_db)) -> ApplicationService:
    return ApplicationService(db)


def get_refresh_token_service(db: AsyncDatabase = Depends(get_db)) -> RefreshTokenService:
    return RefreshTokenService(db)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(get_user_service),
) -> UserInDB:
    try:
        payload = verify_access_token(token)
        subject = payload.get("sub")
    except ValueError as error:
        # an expired access token is routine (every 15 minutes) and stays out of the error log
        cause = type(error.__cause__).__name__
        level = logging.INFO if cause == "ExpiredSignatureError" else logging.WARNING
        logger.log(level, "event=access_token_rejected reason=%s", cause)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    user = await user_service.get_by_id(subject)
    if user is None:
        logger.warning("event=access_token_rejected reason=user_not_found user_id=%r", subject)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user

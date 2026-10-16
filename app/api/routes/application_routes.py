from fastapi import APIRouter, Depends

from ...core.deps import get_application_service, get_current_user
from ...models.application_models import ApplicationPublic
from ...models.user_models import UserInDB
from ...services.application_service import ApplicationService

router = APIRouter(prefix="/applications", tags=["applications"])


@router.get("", response_model=list[ApplicationPublic])
async def list_applications(
    _: UserInDB = Depends(get_current_user),
    application_service: ApplicationService = Depends(get_application_service),
):
    """Every registered consuming app and its role vocabulary.

    Public to any authenticated caller — the admin panel and consuming apps
    read their role options from here. Registration itself is not exposed over
    HTTP (see auth-service#5); use `scripts/register_application.py`.
    """
    apps = await application_service.list_applications()
    return [
        ApplicationPublic(id=app.id, display_name=app.display_name, roles=app.roles, default_role=app.default_role)
        for app in apps
    ]

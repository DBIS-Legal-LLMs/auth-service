from pymongo.asynchronous.database import AsyncDatabase

from ..models.application_models import ApplicationCreate, ApplicationInDB

APPLICATIONS_COLLECTION = "applications"


class ApplicationService:
    """Read/write access to the `applications` registry.

    Registration is deliberately not exposed over HTTP (see auth-service#5) —
    it happens through `scripts/register_application.py` or a direct DB write.
    This service is the shared implementation both paths use.
    """

    def __init__(self, db: AsyncDatabase):
        self._db = db

    @property
    def applications(self):
        return self._db[APPLICATIONS_COLLECTION]

    async def list_applications(self) -> list[ApplicationInDB]:
        cursor = self.applications.find({}).sort("_id", 1)
        return [ApplicationInDB(**doc) async for doc in cursor]

    async def get(self, app_id: str) -> ApplicationInDB | None:
        doc = await self.applications.find_one({"_id": app_id})
        return ApplicationInDB(**doc) if doc else None

    async def register(self, app_in: ApplicationCreate, *, overwrite: bool = False) -> ApplicationInDB:
        doc = {
            "_id": app_in.id,
            "display_name": app_in.display_name,
            "roles": [role.model_dump() for role in app_in.roles],
            "default_role": app_in.default_role,
        }

        existing = await self.applications.find_one({"_id": app_in.id})
        if existing and not overwrite:
            raise ValueError("APP_ALREADY_REGISTERED")

        if existing:
            await self.applications.replace_one({"_id": app_in.id}, doc)
        else:
            await self.applications.insert_one(doc)

        return ApplicationInDB(**doc)

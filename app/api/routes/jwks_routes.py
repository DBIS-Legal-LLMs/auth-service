from fastapi import APIRouter

from ...core.jwt import get_jwks

router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
async def jwks():
    return get_jwks()

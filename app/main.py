from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes.auth_routes import router as auth_router
from .api.routes.jwks_routes import router as jwks_router
from .config import get_settings


def create_app() -> FastAPI:
    app = FastAPI(
        title="DBIS auth-service",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    settings = get_settings()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router)
    app.include_router(jwks_router)

    return app


app = create_app()


@app.get("/health")
async def health():
    return {"status": "ok"}

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes.application_routes import router as application_router
from .api.routes.auth_routes import router as auth_router
from .api.routes.jwks_routes import router as jwks_router
from .api.routes.user_routes import router as user_router
from .config import get_settings
from .core.logging_setup import install_error_log, remove_error_log
from .db.mongo import get_database
from .services.refresh_token_service import ensure_indexes


@asynccontextmanager
async def lifespan(_: FastAPI):
    # here and not at import: uvicorn resets the handlers of its own loggers when it starts
    settings = get_settings()
    install_error_log(settings.log_dir, settings.log_retention_days, settings.log_max_file_mb)
    await ensure_indexes(get_database())
    yield
    remove_error_log()


def create_app() -> FastAPI:
    app = FastAPI(
        title="DBIS auth-service",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
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
    app.include_router(application_router)
    app.include_router(user_router)

    return app


app = create_app()


@app.get("/health")
async def health():
    return {"status": "ok", "version": get_settings().app_version}

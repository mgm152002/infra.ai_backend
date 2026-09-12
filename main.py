"""Infra.ai API application composition root."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import (
    admin,
    chat,
    cmdb,
    credentials,
    incidents,
    integrations_config,
    knowledge,
    legacy_workflow,
    operations,
    sse,
    workflow,
)
from app.core.lifespan import worker_lifespan
from app.core.middleware import RequestLoggingMiddleware


def create_app() -> FastAPI:
    application = FastAPI(lifespan=worker_lifespan)

    application.add_middleware(RequestLoggingMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(workflow.router, prefix="/api/v1/workflow", tags=["Workflow"])
    application.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin"])
    application.include_router(sse.router, prefix="/api/v1", tags=["SSE"])
    application.include_router(incidents.router, tags=["Incidents"])
    application.include_router(chat.router, tags=["Chat"])
    application.include_router(integrations_config.router, tags=["Integrations"])
    application.include_router(cmdb.router, tags=["CMDB"])
    application.include_router(knowledge.router, tags=["Knowledge"])
    application.include_router(credentials.router, tags=["Credentials"])
    application.include_router(operations.router, tags=["Operations"])
    application.include_router(legacy_workflow.router, tags=["Workflow"])

    return application


app = create_app()

"""
MedTrust FastAPI Application Entrypoint.
Initializes middleware, CORS policies, routers, exception handlers,
and database persistence.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db.init_db import init_db
from app.api.v1.api_router import api_router
from app.core.exceptions import (
    MedTrustException,
    AccessDeniedError,
    ChecksumMismatchError,
    RecordNotFoundError,
    ConsentNotFoundError,
    IPFSConnectionError,
    FabricGatewayError
)

# Ensure database tables and demo accounts are initialized
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables and seeds exist
    init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Decentralized Healthcare Data and Consent Management Backend API",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
)


# Exception Handlers
@app.exception_handler(AccessDeniedError)
async def access_denied_handler(request: Request, exc: AccessDeniedError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


@app.exception_handler(ChecksumMismatchError)
async def checksum_mismatch_handler(request: Request, exc: ChecksumMismatchError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


@app.exception_handler(RecordNotFoundError)
async def record_not_found_handler(request: Request, exc: RecordNotFoundError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


@app.exception_handler(ConsentNotFoundError)
async def consent_not_found_handler(request: Request, exc: ConsentNotFoundError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


@app.exception_handler(IPFSConnectionError)
async def ipfs_error_handler(request: Request, exc: IPFSConnectionError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


@app.exception_handler(FabricGatewayError)
async def fabric_error_handler(request: Request, exc: FabricGatewayError):
    return JSONResponse(
        status_code=exc.code,
        content={"detail": exc.message, "reason": exc.reason}
    )


# Attach API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "port": settings.PORT,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }

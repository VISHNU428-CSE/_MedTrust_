"""
API Router V1 aggregator.
Assembles all endpoint routers under /api/v1 prefix.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health, auth, records, consents, audit, admin

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & RBAC"])
api_router.include_router(records.router, prefix="/records", tags=["Medical Records"])
api_router.include_router(consents.router, prefix="/consents", tags=["Consent Management"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Trail"])
api_router.include_router(admin.router, prefix="/admin", tags=["Administration"])

"""
Health & Diagnostic Endpoints.
"""

from fastapi import APIRouter
from app.config import settings
from app.models.schemas import HealthResponse
from app.adapters.ipfs_client import ipfs_client
from app.adapters.fabric_gateway import fabric_gateway

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check():
    """
    Returns platform health, versioning, IPFS connection state,
    and Hyperledger Fabric Gateway readiness.
    """
    # IPFS connection inspection
    try:
        ipfs_info = ipfs_client.check_connection()
        ipfs_status = f"connected ({ipfs_info.get('agentVersion', 'Kubo')})"
    except Exception as e:
        ipfs_status = f"standby / offline ({str(e)})"

    # Fabric Gateway status
    fabric_info = fabric_gateway.get_status()
    fabric_status = f"connected ({fabric_info.get('channel')}, {fabric_info.get('records_count')} records on-chain)"

    return HealthResponse(
        online=True,
        version=settings.VERSION,
        status="healthy",
        ipfs_status=ipfs_status,
        fabric_status=fabric_status
    )

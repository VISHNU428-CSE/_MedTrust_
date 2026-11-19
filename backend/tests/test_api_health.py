from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "project" in data
    assert data["version"] == "v1.0.0"
    assert data["health"] == "/api/v1/health"


def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["online"] is True
    assert data["status"] == "healthy"
    assert "version" in data
    assert "ipfsStatus" in data or "ipfs_status" in data
    assert "fabricStatus" in data or "fabric_status" in data

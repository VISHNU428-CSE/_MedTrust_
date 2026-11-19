from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token

client = TestClient(app)


def test_get_audit_logs_unauthenticated_rejected():
    res = client.get("/api/v1/audit")
    assert res.status_code == 401


def test_get_audit_logs():
    token = create_access_token({"sub": "aud-001001", "name": "Federal Auditor", "role": "AUDITOR"})
    res = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    logs = res.json()
    assert len(logs) >= 4
    first = logs[0]
    assert "actorId" in first
    assert "actorRole" in first
    assert "action" in first
    assert "txHash" in first
    assert "entryHash" in first


def test_verify_audit_chain_unauthenticated_rejected():
    res = client.get("/api/v1/audit/verify")
    assert res.status_code == 401


def test_verify_audit_chain():
    token = create_access_token({"sub": "aud-001001", "name": "Federal Auditor", "role": "AUDITOR"})
    res = client.get("/api/v1/audit/verify", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["chainIntact"] is True
    assert "cryptographically intact" in data["message"]

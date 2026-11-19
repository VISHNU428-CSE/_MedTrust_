"""
Pytest configuration and global fixtures for MedTrust QA suite.
"""

import sys
import os
import shutil
import pytest
import time
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure backend package is on sys.path for direct adapter testing
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

PROD_DB_PATH = os.path.join(backend_dir, "medtrust.db")
TEST_DB_PATH = os.path.join(backend_dir, "test_medtrust.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"

# Guarantee environment points to isolated test database
os.environ["DATABASE_URL"] = TEST_DB_URL
if "MEDTRUST_MASTER_KEK" not in os.environ:
    os.environ["MEDTRUST_MASTER_KEK"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="session", autouse=True)
def isolated_test_database():
    """Guarantees tests never modify the production medtrust.db."""
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

    if os.path.exists(PROD_DB_PATH):
        shutil.copy2(PROD_DB_PATH, TEST_DB_PATH)

    import app.db.session as session_mod
    import app.config as config_mod

    test_engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        echo=False
    )
    test_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    orig_engine = session_mod.engine
    orig_SessionLocal = session_mod.SessionLocal
    orig_db_url = config_mod.settings.DATABASE_URL

    session_mod.engine = test_engine
    session_mod.SessionLocal = test_SessionLocal
    config_mod.settings.DATABASE_URL = TEST_DB_URL

    from app.db.init_db import init_db
    init_db()

    yield test_engine

    test_engine.dispose()
    session_mod.engine = orig_engine
    session_mod.SessionLocal = orig_SessionLocal
    config_mod.settings.DATABASE_URL = orig_db_url

    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass


from fixtures.synthetic_records import (
    get_synthetic_ehr_encounter,
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID,
    DOCTOR_DR_JONES_ID,
    ATTACKER_EVE_ID
)
from fixtures.auth_tokens import (
    get_patient_token,
    get_doctor_token,
    get_expired_token,
    get_tampered_signature_token,
    get_role_escalated_token
)
from fixtures.golden_vectors import (
    GOLDEN_VECTORS,
    get_golden_vector,
    verify_golden_digest
)
from core_harness import (
    MockIPFSNode,
    IPFSVerifier,
    ConsentEngine,
    AuditTrailLedger,
    RBACAuthorizer
)
from app.adapters.real_fabric_gateway import RealFabricGatewayClient
from app.adapters.fabric_gateway import FabricGatewayAdapter


@pytest.fixture
def ipfs_node():
    """Provides a fresh simulated IPFS storage node."""
    return MockIPFSNode()


@pytest.fixture
def ipfs_verifier(ipfs_node):
    """Provides an IPFS payload checksum integrity verifier."""
    return IPFSVerifier(ipfs_node)


@pytest.fixture
def consent_engine():
    """Provides a fresh Consent Management state engine."""
    return ConsentEngine()


@pytest.fixture
def audit_ledger():
    """Provides an immutable hash-chained audit trail ledger."""
    return AuditTrailLedger()


@pytest.fixture
def rbac_authorizer(consent_engine, audit_ledger):
    """Provides an RBAC authorization enforcement engine with audit logging."""
    return RBACAuthorizer(consent_engine, audit_ledger)


@pytest.fixture
def fabric_gateway_adapter():
    """Provides a fresh FabricGatewayAdapter instance."""
    return FabricGatewayAdapter()


@pytest.fixture
def real_fabric_client():
    """Provides a fresh RealFabricGatewayClient instance adhering to GATEWAY_ADAPTER_SPEC.md."""
    return RealFabricGatewayClient()


@pytest.fixture
def synthetic_ehr_record():
    """Provides a synthetic general EHR record for Patient Alice."""
    return get_synthetic_ehr_encounter(PATIENT_ALICE_ID)


@pytest.fixture
def synthetic_lab_record():
    """Provides a synthetic lab report for Patient Alice."""
    return get_synthetic_lab_report(PATIENT_ALICE_ID)


@pytest.fixture
def synthetic_cardiology_record():
    """Provides a synthetic cardiology record for Patient Alice."""
    return get_synthetic_cardiology_encounter(PATIENT_ALICE_ID)


@pytest.fixture
def synthetic_radiology_record():
    """Provides a synthetic radiology record for Patient Bob."""
    return get_synthetic_radiology_report(PATIENT_BOB_ID)

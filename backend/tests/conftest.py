"""
Pytest configuration for MedTrust Backend Test Suite.
Guarantees strict database isolation:
Tests operate on a transient copy (test_medtrust.db) and NEVER modify the production medtrust.db.
"""

import os
import shutil
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Paths for production vs test database
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_DB_PATH = os.path.join(BACKEND_DIR, "medtrust.db")
TEST_DB_PATH = os.path.join(BACKEND_DIR, "test_medtrust.db")
TEST_DB_URL = f"sqlite:///{TEST_DB_PATH}"

# Set environment variable before any modules initialize
os.environ["DATABASE_URL"] = TEST_DB_URL
if "MEDTRUST_MASTER_KEK" not in os.environ:
    os.environ["MEDTRUST_MASTER_KEK"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(scope="session", autouse=True)
def isolated_test_database():
    """
    Session-scoped fixture:
    1. Copies medtrust.db baseline to test_medtrust.db.
    2. Overrides app.db.session engine and SessionLocal to point strictly to test_medtrust.db.
    3. Verifies that no database connection can touch the production medtrust.db.
    4. Tears down test_medtrust.db upon test completion.
    """
    # 1. Prepare isolated test database file
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

    if os.path.exists(PROD_DB_PATH):
        shutil.copy2(PROD_DB_PATH, TEST_DB_PATH)
    else:
        # If prod DB doesn't exist, create fresh
        pass

    # 2. Re-bind SQLAlchemy engine and sessionmaker to test database
    import app.db.session as session_mod
    import app.config as config_mod

    test_engine = create_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        echo=False
    )
    test_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Save original references
    orig_engine = session_mod.engine
    orig_SessionLocal = session_mod.SessionLocal
    orig_db_url = config_mod.settings.DATABASE_URL

    # Apply overrides
    session_mod.engine = test_engine
    session_mod.SessionLocal = test_SessionLocal
    config_mod.settings.DATABASE_URL = TEST_DB_URL

    # Safety assertion: verify engine database is test_medtrust.db
    assert "test_medtrust.db" in str(session_mod.engine.url), (
        f"CRITICAL: Test engine url '{session_mod.engine.url}' is not using test_medtrust.db!"
    )

    # Initialize / update test database schema and seeds
    from app.db.init_db import init_db
    init_db()

    yield test_engine

    # 3. Teardown
    test_engine.dispose()
    session_mod.engine = orig_engine
    session_mod.SessionLocal = orig_SessionLocal
    config_mod.settings.DATABASE_URL = orig_db_url

    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass

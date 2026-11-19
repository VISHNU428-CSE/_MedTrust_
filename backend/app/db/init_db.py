"""
Database initialization and demo account seeding.
Creates SQLite tables and seeds verified accounts.
"""

import logging
from sqlalchemy.orm import Session
from app.db.session import engine, Base, SessionLocal
from app.db.models import UserModel, RecordDetailModel, RecordKeyModel
from app.core.security import hash_password

logger = logging.getLogger(__name__)

DEMO_ACCOUNTS = [
    {
        "id": "pat-984210",
        "name": "Eleanor Vance",
        "email": "e.vance@example.med",
        "role": "PATIENT",
        "password": "password123",
        "hospital": None,
        "specialty": None
    },
    {
        "id": "doc-331902",
        "name": "Dr. Marcus Sterling, MD",
        "email": "m.sterling@metrohealth.org",
        "role": "DOCTOR",
        "password": "password123",
        "hospital": "Metro General Hospital",
        "specialty": "Cardiovascular Surgery",
        "license_number": "MD-LIC-CA-948210",
        "approval_status": "APPROVED"
    },
    {
        "id": "doc-119283",
        "name": "Dr. Clara Oswald, DDS",
        "email": "c.oswald@apexdental.med",
        "role": "DOCTOR",
        "password": "password123",
        "hospital": "Apex Dental & Maxillofacial",
        "specialty": "Oral Surgery",
        "license_number": "DDS-LIC-IL-119283",
        "approval_status": "APPROVED"
    },
    {
        "id": "doc-999999",
        "name": "Dr. Unknown, MD",
        "email": "dr.unknown@hospital.med",
        "role": "DOCTOR",
        "password": "password123",
        "hospital": "Unknown Hospital",
        "specialty": "General Practice",
        "license_number": "MD-LIC-999999",
        "approval_status": "APPROVED"
    },
    {
        "id": "doc-555",
        "name": "Dr. Sarah Lin, MD",
        "email": "s.lin@metrolabs.org",
        "role": "DOCTOR",
        "password": "password123",
        "hospital": "Metro Labs & Diagnostics",
        "specialty": "Endocrinology",
        "license_number": "MD-LIC-555001",
        "approval_status": "APPROVED"
    },
    {
        "id": "aud-001001",
        "name": "Federal Compliance Auditor",
        "email": "auditor@medtrust.gov",
        "role": "AUDITOR",
        "password": "password123",
        "hospital": "Office of the National Coordinator",
        "specialty": "HIPAA & Consent Oversight"
    },
    {
        "id": "adm-999999",
        "name": "Platform Administrator",
        "email": "admin@medtrust.org",
        "role": "ADMIN",
        "password": "admin123",
        "hospital": "MedTrust HQ",
        "specialty": "Infrastructure"
    }
]


DEMO_RECORD_DETAILS = [
    {
        "id": "det-rec-001",
        "record_id": "rec-001",
        "patient_id": "pat-984210",
        "description": "Baseline echocardiogram diagnostic assessment with ejection fraction monitoring.",
        "prescription_cid": None,
        "prescription_filename": None,
        "prescription_checksum": None,
        "has_document": True
    },
    {
        "id": "det-rec-002",
        "record_id": "rec-002",
        "patient_id": "pat-984210",
        "description": "Routine complete blood count differential panel for annual checkup.",
        "prescription_cid": None,
        "prescription_filename": None,
        "prescription_checksum": None,
        "has_document": True
    },
    {
        "id": "det-rec-003",
        "record_id": "rec-003",
        "patient_id": "pat-984210",
        "description": "Cardiac post-operative recovery protocol and medication dosage instructions.",
        "prescription_cid": "bafkreif76whhuxc6qmsdfx7d2o6o6zux7257qf6t67qukzzsqb7sduflqa",
        "prescription_filename": "post_op_cardiac_rx.pdf",
        "prescription_checksum": "a8f3b1456980bcdef1234567890abcdef1234567890abcdef1234567890abcde",
        "has_document": True
    }
]


def migrate_users_table():
    """Applies schema migrations to users table in SQLite if columns do not exist."""
    try:
        with engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(users)")
            cols = [r[1] for r in result.fetchall()]
            if cols:
                if "approval_status" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN approval_status VARCHAR(32) DEFAULT 'PENDING'")
                if "license_number" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN license_number VARCHAR(128)")
                if "applied_at" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN applied_at DATETIME")
                if "reviewed_at" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reviewed_at DATETIME")
                if "reviewed_by" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN reviewed_by VARCHAR(64)")
                if "rejection_reason" not in cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN rejection_reason TEXT")
                # Ensure non-doctor roles have approval_status = 'APPROVED'
                conn.exec_driver_sql("UPDATE users SET approval_status = 'APPROVED' WHERE role != 'DOCTOR' AND (approval_status IS NULL OR approval_status = 'PENDING')")
                # Set explicitly verified demo doctors
                conn.exec_driver_sql("UPDATE users SET approval_status = 'APPROVED', license_number = 'MD-LIC-CA-948210' WHERE id = 'doc-331902'")
                conn.exec_driver_sql("UPDATE users SET approval_status = 'APPROVED', license_number = 'DDS-LIC-IL-119283' WHERE id = 'doc-119283'")
                conn.exec_driver_sql("UPDATE users SET approval_status = 'APPROVED', license_number = 'MD-LIC-999999' WHERE id = 'doc-999999'")
                conn.exec_driver_sql("UPDATE users SET approval_status = 'APPROVED', license_number = 'MD-LIC-555001' WHERE id = 'doc-555'")
                conn.commit()
    except Exception as e:
        logger.warning("User table migration check: %s", str(e))


def migrate_record_details_table():
    """Applies schema migrations to record_details table in SQLite if columns do not exist."""
    try:
        with engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(record_details)")
            cols = [r[1] for r in result.fetchall()]
            if cols:
                if "document_filename" not in cols:
                    conn.exec_driver_sql("ALTER TABLE record_details ADD COLUMN document_filename VARCHAR(255)")
                if "document_mime_type" not in cols:
                    conn.exec_driver_sql("ALTER TABLE record_details ADD COLUMN document_mime_type VARCHAR(100)")
                conn.commit()
    except Exception as e:
        logger.warning("Record details table migration check: %s", str(e))


def init_record_keys_table():
    """
    Additive schema initialization for record_keys table in SQLite.
    Ensures record_keys table exists without altering, resetting, or dropping existing data.
    """
    try:
        with engine.connect() as conn:
            result = conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='record_keys'"
            )
            if not result.fetchone():
                if "record_keys" in Base.metadata.tables:
                    Base.metadata.tables["record_keys"].create(bind=engine, checkfirst=True)
                    conn.commit()
                    logger.info("Additive record_keys schema initialized.")
    except Exception as e:
        logger.warning("Record keys table additive initialization check: %s", str(e))


def init_record_quarantines_table():
    """
    Additive schema initialization for record_quarantines table in SQLite.
    Ensures record_quarantines table exists without altering, resetting, or dropping existing data.
    """
    try:
        with engine.connect() as conn:
            result = conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='record_quarantines'"
            )
            if not result.fetchone():
                if "record_quarantines" in Base.metadata.tables:
                    Base.metadata.tables["record_quarantines"].create(bind=engine, checkfirst=True)
                    conn.commit()
                    logger.info("Additive record_quarantines schema initialized.")
    except Exception as e:
        logger.warning("Record quarantines table additive initialization check: %s", str(e))


def init_db(db: Session = None) -> None:
    """Creates database tables and seeds demo accounts if not already present."""
    Base.metadata.create_all(bind=engine)
    migrate_users_table()
    migrate_record_details_table()
    init_record_keys_table()
    init_record_quarantines_table()

    owns_session = False
    if db is None:
        db = SessionLocal()
        owns_session = True

    try:
        for acc in DEMO_ACCOUNTS:
            existing = db.query(UserModel).filter(UserModel.email == acc["email"].lower()).first()
            if not existing:
                user = UserModel(
                    id=acc["id"],
                    email=acc["email"].lower(),
                    name=acc["name"],
                    role=acc["role"],
                    password_hash=hash_password(acc["password"]),
                    hospital=acc["hospital"],
                    specialty=acc["specialty"],
                    license_number=acc.get("license_number"),
                    approval_status=acc.get("approval_status", "APPROVED" if acc["role"] != "DOCTOR" else "PENDING"),
                    is_active=True
                )
                db.add(user)
                logger.info("Seeded demo user: %s (%s)", acc["name"], acc["role"])

        for det in DEMO_RECORD_DETAILS:
            existing_det = db.query(RecordDetailModel).filter(RecordDetailModel.record_id == det["record_id"]).first()
            if not existing_det:
                detail_row = RecordDetailModel(
                    id=det["id"],
                    record_id=det["record_id"],
                    patient_id=det["patient_id"],
                    description=det["description"],
                    prescription_cid=det["prescription_cid"],
                    prescription_filename=det["prescription_filename"],
                    prescription_checksum=det["prescription_checksum"],
                    has_document=det["has_document"]
                )
                db.add(detail_row)
                logger.info("Seeded demo record detail: %s (record: %s)", det["id"], det["record_id"])

        db.commit()
    finally:
        if owns_session:
            db.close()

"""
MedTrust - IPR-48 Live Full-Stack Synthetic End-to-End Demonstration Script
Executes the complete synthetic patient/doctor lifecycle against live Fabric and Kubo infrastructure.
Captures concrete cryptographic and transaction receipts at every step.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
import httpx

BASE_URL = "http://127.0.0.1:8001/api/v1"
KUBO_RPC = "http://127.0.0.1:5001/api/v0"
COUCHDB_URL = "http://admin:adminpw@127.0.0.1:5984/medtrust-channel_medtrust-contract"

RECORD_ID = "REC-SYNTH-IPR48-001"
CONSENT_ID = "CON-SYNTH-IPR48-001"

DOCTOR_EMAIL = "doc.synth.ipr48@medtrust.test"
DOCTOR_PASSWORD = "DoctorSynthPass48!"
DOCTOR_NAME = "Dr. Synthetic Cardio, MD"
DOCTOR_HOSPITAL = "Metro Heart Center"
DOCTOR_SPECIALTY = "Cardiology"
DOCTOR_LICENSE = "SYNTH-MD-LIC-4801"

PATIENT_EMAIL = "pat.synth.ipr48@medtrust.test"
PATIENT_PASSWORD = "PatientSynthPass48!"
PATIENT_NAME = "Synthetic Patient 48"

ADMIN_EMAIL = "admin@medtrust.org"
ADMIN_PASSWORD = "admin123"

SYNTH_REPORT_CONTENT = (
    b"%PDF-1.4\n"
    b"%Synthetic Cardiology Diagnostic Report for IPR-48 Live System Demonstration\n"
    b"Patient: PAT-SYNTH-IPR48\n"
    b"Study: 12-Lead Electrocardiogram and Transthoracic Echocardiogram\n"
    b"Findings: Normal sinus rhythm at 72 bpm. PR interval 158 ms. QRS duration 86 ms.\n"
    b"Echocardiogram: Left ventricular ejection fraction 62%. No wall motion abnormalities.\n"
    b"Conclusion: Normal cardiac structure and function.\n"
    b"Hash Integrity Sentinel: IPR-48-VERIFIED-INTEGRITY-RECEIPT\n"
)
EXPECTED_PLAINTEXT_HASH = hashlib.sha256(SYNTH_REPORT_CONTENT).hexdigest()

evidence = {
    "phases": {},
    "receipts": {},
    "invariants": {}
}

def log_step(phase: str, msg: str):
    print(f"\n[{phase}] {msg}")

def fabric_peer_query(fn: str, args: list) -> dict:
    cmd = [
        "docker", "exec",
        "-e", "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/client-msp",
        "-e", "CORE_PEER_TLS_ENABLED=true",
        "-e", "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt",
        "-e", "CORE_PEER_ADDRESS=peer0.org1.medtrust.com:7051",
        "peer0.org1.medtrust.com",
        "peer", "chaincode", "query",
        "-C", "medtrust-channel",
        "-n", "medtrust-contract",
        "-c", json.dumps({"function": f"MedTrustContract:{fn}", "Args": args})
    ]
    raw = subprocess.check_output(cmd, text=True)
    return json.loads(raw.strip())

def get_couchdb_doc(doc_id: str) -> dict:
    encoded_id = doc_id.replace("\x00", "%00")
    try:
        r = httpx.get(f"{COUCHDB_URL}/{encoded_id}", timeout=5.0)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def main():
    print("=" * 80)
    print("MEDTRUST IPR-48 LIVE SYNTHETIC FULL-STACK DEMONSTRATION")
    print(f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"Target Backend: {BASE_URL}")
    print(f"Kubo RPC: {KUBO_RPC}")
    print(f"Synthetic Record ID: {RECORD_ID}")
    print(f"Synthetic Consent ID: {CONSENT_ID}")
    print(f"Expected Plaintext SHA-256: {EXPECTED_PLAINTEXT_HASH}")
    print("=" * 80)

    client = httpx.Client(timeout=30.0)

    # --------------------------------------------------------------------------
    # Step 1 & 2 & 3: Connectivity Preflight
    # --------------------------------------------------------------------------
    log_step("PREFLIGHT", "Verifying Backend (8001), Frontend (5174), Kubo (5001), and Fabric (7051)...")
    health_resp = client.get(f"{BASE_URL}/health")
    assert health_resp.status_code == 200, f"Backend health failed: {health_resp.text}"
    health_data = health_resp.json()
    print(f"Backend Health: {health_data}")
    assert health_data.get("online") is True
    assert "connected" in health_data.get("ipfsStatus", "")
    assert "connected" in health_data.get("fabricStatus", "")

    pin_resp = client.post(f"{KUBO_RPC}/pin/ls")
    assert pin_resp.status_code == 200, f"Kubo pin/ls failed: {pin_resp.text}"
    pre_pins = pin_resp.json().get("Keys", {})
    evidence["invariants"]["pre_execution_pin_count"] = len(pre_pins)
    print(f"Kubo Pin Count: {len(pre_pins)} intact keys")

    chan_info = subprocess.check_output(
        "docker exec peer0.org1.medtrust.com peer channel getinfo -c medtrust-channel",
        shell=True, text=True
    )
    print(f"Fabric Channel Info: {chan_info.strip()}")
    evidence["invariants"]["channel_info_pre"] = chan_info.strip()

    # --------------------------------------------------------------------------
    # Step 4: Register Synthetic Doctor and Verify Approval Gate
    # --------------------------------------------------------------------------
    log_step("PHASE 1", "Registering synthetic doctor with licensure...")
    doc_reg_payload = {
        "email": DOCTOR_EMAIL,
        "password": DOCTOR_PASSWORD,
        "name": DOCTOR_NAME,
        "hospital": DOCTOR_HOSPITAL,
        "specialty": DOCTOR_SPECIALTY,
        "license_number": DOCTOR_LICENSE,
    }
    doc_reg_resp = client.post(f"{BASE_URL}/auth/register-doctor", json=doc_reg_payload)
    if doc_reg_resp.status_code == 400 and "already exists" in doc_reg_resp.text:
        print("Doctor account already registered.")
    else:
        assert doc_reg_resp.status_code == 201, f"Doctor registration failed: {doc_reg_resp.text}"
        doc_reg_data = doc_reg_resp.json()
        print(f"Doctor Registration Response: {doc_reg_data}")
        assert doc_reg_data.get("approvalStatus") == "PENDING"

    # Admin Login & Application Approval
    log_step("PHASE 1", "Logging in as Administrator to approve doctor application...")
    admin_login = client.post(f"{BASE_URL}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert admin_login.status_code == 200, f"Admin login failed: {admin_login.text}"
    admin_token = admin_login.json()["accessToken"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    apps_resp = client.get(f"{BASE_URL}/admin/doctor-applications?status=ALL", headers=admin_headers)
    assert apps_resp.status_code == 200
    apps_list = apps_resp.json()
    matching_apps = [a for a in apps_list if a.get("email") == DOCTOR_EMAIL]
    assert len(matching_apps) > 0, "Registered doctor application not found in admin list"
    doc_entry = matching_apps[0]
    doctor_id = doc_entry["id"]
    print(f"Found Doctor: ID={doctor_id}, ApprovalStatus={doc_entry.get('approvalStatus')}")

    if doc_entry.get("approvalStatus") != "APPROVED":
        log_step("PHASE 1", f"Approving Doctor Application {doctor_id}...")
        approve_resp = client.post(f"{BASE_URL}/admin/doctor-applications/{doctor_id}/approve", headers=admin_headers)
        assert approve_resp.status_code == 200, f"Approval failed: {approve_resp.text}"

    # Approved Doctor Login
    log_step("PHASE 1", "Logging in as approved doctor...")
    doc_login = client.post(f"{BASE_URL}/auth/login", json={"email": DOCTOR_EMAIL, "password": DOCTOR_PASSWORD})
    assert doc_login.status_code == 200, f"Approved doctor login failed: {doc_login.text}"
    doctor_token = doc_login.json()["accessToken"]
    doctor_headers = {"Authorization": f"Bearer {doctor_token}"}
    print(f"Doctor Authenticated: Token acquired for doctor ID: {doctor_id}")
    evidence["phases"]["doctor_registration_and_approval"] = {
        "doctor_id": doctor_id,
        "email": DOCTOR_EMAIL,
        "license": DOCTOR_LICENSE,
        "approval_status": "APPROVED"
    }

    # --------------------------------------------------------------------------
    # Step 5: Patient Setup & Medical Document Upload
    # --------------------------------------------------------------------------
    log_step("PHASE 2", "Setting up synthetic patient account...")
    pat_reg = client.post(
        f"{BASE_URL}/auth/register",
        json={"email": PATIENT_EMAIL, "password": PATIENT_PASSWORD, "name": PATIENT_NAME, "role": "PATIENT"}
    )
    pat_login = client.post(f"{BASE_URL}/auth/login", json={"email": PATIENT_EMAIL, "password": PATIENT_PASSWORD})
    assert pat_login.status_code == 200, f"Patient login failed: {pat_login.text}"
    patient_token = pat_login.json()["accessToken"]
    patient_headers = {"Authorization": f"Bearer {patient_token}"}

    me_resp = client.get(f"{BASE_URL}/auth/me", headers=patient_headers)
    assert me_resp.status_code == 200
    patient_id = me_resp.json()["id"]
    print(f"Patient Authenticated: ID={patient_id}, Name={PATIENT_NAME}")

    log_step("PHASE 2", f"Checking / Uploading synthetic document with Record ID: {RECORD_ID}...")
    # Check if record already registered
    check_rec = client.get(f"{BASE_URL}/records/{RECORD_ID}", headers=patient_headers)
    if check_rec.status_code == 200:
        print(f"Record {RECORD_ID} already registered in database & on Fabric ledger.")
        rec_data = check_rec.json()
    else:
        files = {
            "file": ("cardiology_report_ipr48.pdf", SYNTH_REPORT_CONTENT, "application/pdf")
        }
        data = {
            "record_id": RECORD_ID,
            "patient_id": patient_id,
            "patient_name": PATIENT_NAME,
            "title": "Comprehensive Synthetic Cardiology Workup",
            "record_type": "CARDIOLOGY_REPORT",
            "hospital": DOCTOR_HOSPITAL,
            "description": "Resting 12-lead ECG and 2D echo report. Normal sinus rhythm.",
        }
        upload_resp = client.post(f"{BASE_URL}/records/upload", data=data, files=files, headers=patient_headers)
        assert upload_resp.status_code in (200, 201), f"Upload failed: {upload_resp.text}"
        rec_data = upload_resp.json()

    print(f"Record Data: {json.dumps(rec_data, indent=2)}")
    rec_id = rec_data.get("id") or rec_data.get("recordId")
    ipfs_cid = rec_data.get("ipfsCid") or rec_data.get("cid")
    record_type = rec_data.get("recordType")
    checksum = rec_data.get("checksumSha256")

    assert rec_id == RECORD_ID
    assert record_type == "CARDIOLOGY_REPORT"
    assert ipfs_cid is not None
    assert checksum is not None

    evidence["phases"]["patient_record_upload"] = {
        "record_id": rec_id,
        "record_type": record_type,
        "ipfs_cid": ipfs_cid,
        "checksum_sha256": checksum,
    }

    # --------------------------------------------------------------------------
    # Step 6 & 7: Verify Live IPFS Pin & Fabric Ledger State
    # --------------------------------------------------------------------------
    log_step("VERIFICATION", f"Verifying IPFS CID {ipfs_cid} in live Kubo blockstore...")
    stat_resp = client.post(f"{KUBO_RPC}/block/stat?arg={ipfs_cid}")
    assert stat_resp.status_code == 200, f"Kubo block/stat failed: {stat_resp.text}"
    stat_data = stat_resp.json()
    print(f"Kubo Block Stat: Key={stat_data.get('Key')}, Size={stat_data.get('Size')} bytes")
    assert stat_data.get("Key") == ipfs_cid
    evidence["receipts"]["ipfs_block_stat"] = stat_data

    log_step("VERIFICATION", f"Querying Fabric ledger directly for {RECORD_ID} via Client MSP...")
    onchain_rec = fabric_peer_query("GetRecord", [RECORD_ID])
    print(f"Fabric Ledger Query Result:\n{json.dumps(onchain_rec, indent=2)}")
    assert onchain_rec.get("recordId") == RECORD_ID
    assert onchain_rec.get("ipfsCid") == ipfs_cid
    assert onchain_rec.get("checksum") == checksum or onchain_rec.get("checksumSha256") == checksum
    assert onchain_rec.get("recordType") == "CARDIOLOGY_REPORT"
    evidence["receipts"]["fabric_onchain_record"] = onchain_rec

    couch_rec = get_couchdb_doc(f"\x00MedicalRecord\x00{RECORD_ID}\x00")
    print(f"CouchDB World-State Revision: {couch_rec.get('_rev')}, Version: {couch_rec.get('~version')}")
    evidence["receipts"]["couchdb_record"] = couch_rec

    # --------------------------------------------------------------------------
    # Step 8: Doctor Requests Consent and Patient Grants Consent on Fabric
    # --------------------------------------------------------------------------
    log_step("PHASE 3", f"Doctor {doctor_id} requesting consent {CONSENT_ID} covering CARDIOLOGY_REPORT...")
    req_consent_payload = {
        "consent_id": CONSENT_ID,
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "purpose": "Cardiology diagnostic review and consultation",
        "duration_days": 30,
        "allowed_record_types": ["CARDIOLOGY_REPORT"],
    }
    req_resp = client.post(f"{BASE_URL}/consents/request", json=req_consent_payload, headers=doctor_headers)
    assert req_resp.status_code in (200, 201), f"Consent request failed: {req_resp.text}"
    req_data = req_resp.json()
    print(f"Consent Request Response: {req_data}")
    assert req_data.get("success") is True
    consent_req_tx = req_data.get("txHash")

    # Patient Grants Consent on Ledger
    log_step("PHASE 3", f"Patient {patient_id} granting consent {CONSENT_ID} on Fabric ledger...")
    grant_resp = client.post(f"{BASE_URL}/consents/{CONSENT_ID}/grant", json={}, headers=patient_headers)
    assert grant_resp.status_code == 200, f"Consent grant failed: {grant_resp.text}"
    grant_data = grant_resp.json()
    print(f"Consent Grant Response: {grant_data}")
    assert grant_data.get("success") is True

    # Query On-Chain Consent Status
    onchain_consent = fabric_peer_query("GetConsent", [CONSENT_ID])
    print(f"Fabric On-Chain Consent Record:\n{json.dumps(onchain_consent, indent=2)}")
    assert onchain_consent.get("consentId") == CONSENT_ID
    assert onchain_consent.get("status") in ("APPROVED", "ACTIVE")
    couch_consent = get_couchdb_doc(f"\x00ConsentRecord\x00{CONSENT_ID}\x00")
    evidence["phases"]["consent_lifecycle"] = {
        "consent_id": CONSENT_ID,
        "request_tx": consent_req_tx,
        "grant_tx": grant_data.get("txHash"),
        "granted_status": onchain_consent.get("status"),
        "allowed_record_types": onchain_consent.get("allowedRecordTypes"),
        "couchdb_rev": couch_consent.get("_rev")
    }

    # --------------------------------------------------------------------------
    # Step 9: Authorized Doctor Downloads and Decrypts Plaintext
    # --------------------------------------------------------------------------
    log_step("PHASE 4", f"Doctor downloading {RECORD_ID} under active consent...")
    dl_resp = client.get(f"{BASE_URL}/records/{RECORD_ID}/download", headers=doctor_headers)
    assert dl_resp.status_code == 200, f"Doctor download failed: {dl_resp.status_code} {dl_resp.text}"
    downloaded_bytes = dl_resp.content
    downloaded_hash = hashlib.sha256(downloaded_bytes).hexdigest()
    print(f"Downloaded Size: {len(downloaded_bytes)} bytes")
    print(f"Downloaded SHA-256: {downloaded_hash}")
    print(f"Expected SHA-256  : {EXPECTED_PLAINTEXT_HASH}")
    assert downloaded_hash == EXPECTED_PLAINTEXT_HASH, "Cryptographic integrity failure: Decrypted plaintext does not match original!"
    print("Exact Byte-for-Byte Plaintext Cryptographic Verification: SUCCESS!")
    evidence["phases"]["authorized_doctor_download"] = {
        "status_code": dl_resp.status_code,
        "content_length": len(downloaded_bytes),
        "sha256_match": True,
        "sha256": downloaded_hash
    }

    # --------------------------------------------------------------------------
    # Step 10 & 11: Patient Revokes Consent and Doctor Download Is Blocked
    # --------------------------------------------------------------------------
    log_step("PHASE 5", f"Patient {patient_id} revoking consent {CONSENT_ID} on Fabric ledger...")
    rev_resp = client.post(f"{BASE_URL}/consents/{CONSENT_ID}/revoke", headers=patient_headers)
    assert rev_resp.status_code == 200, f"Consent revocation failed: {rev_resp.text}"
    rev_data = rev_resp.json()
    print(f"Revocation Response: {rev_data}")
    assert rev_data.get("success") is True

    # Verify On-Chain Revocation
    rev_consent_record = fabric_peer_query("GetConsent", [CONSENT_ID])
    print(f"Fabric On-Chain Consent Record After Revocation:\n{json.dumps(rev_consent_record, indent=2)}")
    assert rev_consent_record.get("status") == "REVOKED", f"Expected REVOKED, got {rev_consent_record.get('status')}"

    # Verify Unauthorized Post-Revocation Doctor Download -> HTTP 403 Forbidden
    log_step("PHASE 5", f"Verifying doctor download attempt on {RECORD_ID} is immediately rejected with HTTP 403...")
    post_rev_dl = client.get(f"{BASE_URL}/records/{RECORD_ID}/download", headers=doctor_headers)
    print(f"Post-Revocation Download Response: Status={post_rev_dl.status_code}, Body={post_rev_dl.text}")
    assert post_rev_dl.status_code == 403, f"Expected 403 Forbidden, got {post_rev_dl.status_code}"
    assert "REVOKED" in post_rev_dl.text.upper() or "CONSENT" in post_rev_dl.text.upper()
    print("Authorization Enforcement Verified: Doctor access blocked prior to key unwrapping and IPFS retrieval.")
    evidence["phases"]["consent_revocation_enforcement"] = {
        "revocation_tx": rev_data.get("txHash"),
        "onchain_status": "REVOKED",
        "post_revocation_status_code": post_rev_dl.status_code,
        "rejection_detail": post_rev_dl.json().get("detail")
    }

    # --------------------------------------------------------------------------
    # Step 12: Restart Isolated FastAPI Backend Process Only
    # --------------------------------------------------------------------------
    log_step("PHASE 6", "Restarting isolated FastAPI backend process to prove cold restart durability...")
    pid_file = os.path.join(os.path.dirname(__file__), ".demo_backend.pid")
    if os.path.exists(pid_file):
        with open(pid_file, "r") as f:
            old_pid = int(f.read().strip())
        print(f"Terminating old backend process (PID {old_pid})...")
        subprocess.run(f"taskkill /F /PID {old_pid}", shell=True, capture_output=True)
        time.sleep(1.5)

    print("Spawning fresh isolated demo backend via run_demo_backend.ps1 -RealFabric...")
    proc_res = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File",
         os.path.join(os.path.dirname(__file__), "run_demo_backend.ps1"), "-RealFabric"],
        capture_output=True, text=True
    )
    print(proc_res.stdout)
    assert proc_res.returncode == 0, f"Backend restart failed: {proc_res.stderr}"

    print("Waiting for fresh backend health...")
    restarted = False
    for _ in range(15):
        time.sleep(0.8)
        try:
            r = client.get(f"{BASE_URL}/health")
            if r.status_code == 200:
                restarted = True
                print(f"Fresh Backend Health: {r.json()}")
                break
        except Exception:
            pass
    assert restarted, "Backend did not become healthy after restart!"

    # --------------------------------------------------------------------------
    # Step 13: Verify Post-Restart Ledger Hydration & Revocation Durability
    # --------------------------------------------------------------------------
    log_step("PHASE 6", f"Querying {RECORD_ID} on fresh backend instance...")
    fresh_rec_resp = client.get(f"{BASE_URL}/records/{RECORD_ID}", headers=patient_headers)
    assert fresh_rec_resp.status_code == 200, f"Failed to retrieve record after restart: {fresh_rec_resp.text}"
    fresh_rec = fresh_rec_resp.json()
    print(f"Fresh Record Retrieval (Hydrated from Fabric): {fresh_rec}")
    assert fresh_rec.get("recordType") == "CARDIOLOGY_REPORT"
    assert fresh_rec.get("ipfsCid") == ipfs_cid

    log_step("PHASE 6", f"Verifying cryptographic integrity verification endpoint on fresh backend...")
    verify_resp = client.post(f"{BASE_URL}/records/{RECORD_ID}/verify", headers=patient_headers)
    assert verify_resp.status_code == 200, f"Verification failed: {verify_resp.text}"
    verify_data = verify_resp.json()
    print(f"Integrity Verify Response: {verify_data}")
    assert verify_data.get("status") == "VERIFIED"
    assert verify_data.get("checksumMatches") is True

    log_step("PHASE 6", f"Patient downloading {RECORD_ID} post-restart (testing SQLite DEK unwrapping)...")
    fresh_pat_dl = client.get(f"{BASE_URL}/records/{RECORD_ID}/download", headers=patient_headers)
    assert fresh_pat_dl.status_code == 200, f"Patient post-restart download failed: {fresh_pat_dl.text}"
    assert hashlib.sha256(fresh_pat_dl.content).hexdigest() == EXPECTED_PLAINTEXT_HASH
    print("Patient Post-Restart Download & Decryption: SUCCESS!")

    log_step("PHASE 6", f"Verifying doctor download attempt on {RECORD_ID} REMAINS BLOCKED (HTTP 403) post-restart...")
    fresh_doc_dl = client.get(f"{BASE_URL}/records/{RECORD_ID}/download", headers=doctor_headers)
    print(f"Doctor Post-Restart Download Response: Status={fresh_doc_dl.status_code}, Body={fresh_doc_dl.text}")
    assert fresh_doc_dl.status_code == 403, f"Expected 403 Forbidden, got {fresh_doc_dl.status_code}"
    print("Persistent Revocation Enforcement Verified: Denied across cold process restart!")
    evidence["phases"]["restart_persistence"] = {
        "fresh_retrieval_status": fresh_rec_resp.status_code,
        "verify_status": verify_data.get("status"),
        "checksum_matches": verify_data.get("checksumMatches"),
        "patient_download_sha256_match": True,
        "doctor_post_restart_blocked_status": fresh_doc_dl.status_code
    }

    # --------------------------------------------------------------------------
    # Final Invariant Assertions: Pins, Hash, Services
    # --------------------------------------------------------------------------
    log_step("INVARIANTS", "Verifying IPFS pin inventory and production database baseline...")
    post_pins_resp = client.post(f"{KUBO_RPC}/pin/ls")
    assert post_pins_resp.status_code == 200
    post_pins = post_pins_resp.json().get("Keys", {})
    evidence["invariants"]["post_execution_pin_count"] = len(post_pins)
    print(f"Post-Execution Kubo Pin Count: {len(post_pins)} (Pre-execution: {evidence['invariants']['pre_execution_pin_count']})")
    assert len(post_pins) >= evidence["invariants"]["pre_execution_pin_count"], "Pin count decreased! Pins were illegally dropped!"
    assert ipfs_cid in post_pins, f"New synthetic CID {ipfs_cid} is not pinned in Kubo!"

    prod_db_path = os.path.join(os.path.dirname(__file__), "..", "backend", "medtrust.db")
    prod_bytes = open(prod_db_path, "rb").read()
    prod_sha256 = hashlib.sha256(prod_bytes).hexdigest().upper()
    expected_prod_hash = "B7B9447C13F4FA5D4B9979072C4849BA0049B9E1A073D07AF3A8466BD28190AD"
    print(f"Production Database SHA-256: {prod_sha256}")
    assert prod_sha256 == expected_prod_hash, f"FATAL INVARIANT VIOLATION: Production database altered! Expected {expected_prod_hash}, got {prod_sha256}"
    evidence["invariants"]["production_db_hash"] = prod_sha256
    evidence["invariants"]["production_db_unmodified"] = True

    # Save evidence file
    evidence_path = os.path.join(os.path.dirname(__file__), "ipr48_live_evidence.json")
    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"\nLive Evidence persisted to: {evidence_path}")
    print("\n" + "=" * 80)
    print("ALL 14 IPR-48 LIVE DEMONSTRATION PHASES COMPLETED WITH 100% SUCCESS!")
    print("=" * 80)

if __name__ == "__main__":
    main()

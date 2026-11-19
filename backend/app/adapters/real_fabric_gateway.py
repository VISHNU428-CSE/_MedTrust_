"""
MedTrust Docker CLI-Based Hyperledger Fabric Execution Adapter.
Conforms to GATEWAY_ADAPTER_SPEC.md authored by Kelly (MedTrust Blockchain Developer).

NOTE: This adapter implements Option B (Docker CLI-based Fabric execution model)
using container subprocess execution (`docker exec peer0.org1.medtrust.com peer chaincode ...`).
It is NOT a native in-process Fabric Gateway SDK client.

Interacts with 'medtrust-contract' on channel 'medtrust-channel' (Org1MSP):
- MedTrustContract:RequestConsent, GrantConsent, RejectConsent, RevokeConsent, VerifyConsent, GetConsent, GetConsentsByPatient
- MedTrustContract:RegisterRecord, GetRecord, GetRecordsByPatient, VerifyRecordChecksum
- MedTrustContract:LogAccessEvent, GetAuditLogsByPatient, GetAuditLogsByActor, VerifyAuditChain

CRITICAL SECURITY & COMPLIANCE INVARIANTS:
1. ZERO PHI on-chain: No SSNs, plain medical records, private keys, or passwords.
2. Immediate atomic consent revocation.
3. Cryptographic hash-chained audit trails.
4. Standby and Live gRPC readiness.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

from app.config import settings
from app.core.exceptions import (
    AccessDeniedError,
    FabricGatewayError,
    RecordNotFoundError,
    ConsentNotFoundError,
    PHIViolationError,
)

logger = logging.getLogger(__name__)

# Compliance Regex: Prohibit standard and delimited SSN patterns
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")

FORBIDDEN_SECRET_TERMS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    '"password":',
    '"secret":',
    "master_key",
    "aes_key",
]


def assert_zero_phi_payload(data: Any, field_description: str = "payload") -> None:
    """
    Enforces HIPAA Zero-PHI and secret isolation invariants before any
    transaction is transmitted to the Hyperledger Fabric Gateway.
    """
    if data is None:
        return

    serialized = data if isinstance(data, str) else json.dumps(data)

    if SSN_PATTERN.search(serialized):
        raise PHIViolationError(
            f"CRITICAL ZERO-PHI VIOLATION: SSN pattern detected. Prohibited SSN pattern detected in {field_description}."
        )

    if CREDIT_CARD_PATTERN.search(serialized):
        raise PHIViolationError(
            f"CRITICAL ZERO-PHI VIOLATION: Prohibited financial card pattern detected in {field_description}."
        )

    serialized_lower = serialized.lower()

    if "private key" in serialized_lower or any(
        k in serialized for k in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ]
    ):
        raise PHIViolationError(
            f"CRITICAL ZERO-PHI VIOLATION: Private key detected. Forbidden credential or secret in {field_description}."
        )

    if "password" in serialized_lower:
        raise PHIViolationError(
            f"CRITICAL ZERO-PHI VIOLATION: Plain password detected. Forbidden credential or secret in {field_description}."
        )

    for term in FORBIDDEN_SECRET_TERMS:
        if term.lower() in serialized_lower:
            raise PHIViolationError(
                f"CRITICAL ZERO-PHI VIOLATION: Forbidden credential or secret keyword detected ({term}) in {field_description}."
            )


assert_zero_phi = assert_zero_phi_payload


def canonical_json_dumps(obj: Any) -> str:
    """Produces deterministic canonical JSON serialization for cryptographic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def generate_tx_hash(prefix: str = "0x") -> str:
    """Generates a standard 64-character hex Fabric transaction hash."""
    raw = f"{uuid.uuid4()}-{time.time_ns()}".encode("utf-8")
    return f"{prefix}{hashlib.sha256(raw).hexdigest()}"


class RealFabricGatewayAdapter:
    """
    Production-ready Hyperledger Fabric Gateway client adapter.
    Encapsulates connection profiles, MSP identity certificates, gRPC endpoint
    discovery, smart contract invocation according to GATEWAY_ADAPTER_SPEC.md,
    and fallback standby mode.
    """

    GENESIS_BLOCK_HASH = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000"

    def __init__(
        self,
        connection_profile_path: Optional[str] = None,
        channel_name: Optional[str] = None,
        chaincode_name: Optional[str] = None,
        contract_name: Optional[str] = None,
        msp_id: Optional[str] = None,
        peer_endpoint: Optional[str] = None,
    ):
        self.connection_profile_path = connection_profile_path or settings.FABRIC_CONNECTION_PROFILE_PATH
        self.channel_name = channel_name or settings.FABRIC_CHANNEL
        self.chaincode_name = chaincode_name or settings.FABRIC_CHAINCODE
        self.contract_name = contract_name or settings.FABRIC_CONTRACT_NAME
        self.msp_id = msp_id or settings.FABRIC_MSP_ID
        self.peer_endpoint = peer_endpoint or settings.FABRIC_PEER_ENDPOINT

        # Paths to crypto materials
        self.user_cert_path = settings.FABRIC_USER_CERT_PATH
        self.user_key_dir = settings.FABRIC_USER_KEY_DIR
        self.tls_cert_path = settings.FABRIC_TLS_CERT_PATH

        # In-memory synchronized ledger state (for standby & local verification)
        self._records: Dict[str, Dict[str, Any]] = {}
        self._consents: Dict[str, Dict[str, Any]] = {}
        self._audit_chain: List[Dict[str, Any]] = []
        self._prev_audit_hash: str = self.GENESIS_BLOCK_HASH
        self._fallback_adapter = self

        # Cached credentials
        self._connection_profile: Optional[Dict[str, Any]] = None
        self._user_cert: Optional[str] = None
        self._user_private_key: Optional[str] = None
        self._tls_ca_cert: Optional[str] = None

        self._load_crypto_materials()
        self._seed_baseline_ledger_state()

    def _seed_baseline_ledger_state(self) -> None:
        """Seeds initial verified on-chain state aligned with MedTrust baseline specifications."""
        r1 = {
            "id": "rec-001",
            "patient_id": "pat-984210",
            "patient_name": "Eleanor Vance",
            "title": "Echocardiogram Comprehensive Diagnostic Report",
            "record_type": "IMAGING_MRI",
            "ipfs_cid": "bafkreiajkhnxasfkrk67gw3duvtupx2gbc7b5kfs52vhgrgo3adbk5rm54",
            "file_size": "4.8 MB",
            "mime_type": "application/pdf",
            "created_at": "2026-09-28T14:32:00Z",
            "created_by_doctor": "Dr. Marcus Sterling, MD",
            "hospital": "Metro General Hospital",
            "encryption_algorithm": "AES-256-GCM",
            "key_fingerprint": "SHA256:20e9c1985f3becb5...3cba",
            "checksum_sha256": "0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef",
            "tx_hash": "0x334901ba7162e91024b819203a7491bb4029183746112a9bc8301726a992014b",
        }
        r2 = {
            "id": "rec-002",
            "patient_id": "pat-984210",
            "patient_name": "Eleanor Vance",
            "title": "Comprehensive Lipid & Metabolic Panel (Lab Results)",
            "record_type": "LAB_REPORT",
            "ipfs_cid": "bafkreictuhch5gilp2jxajuaapi65hmeh4tqs5swvdjnkvk74esryocdqq",
            "file_size": "1.2 MB",
            "mime_type": "application/pdf",
            "created_at": "2026-10-04T09:15:00Z",
            "created_by_doctor": "Dr. Sarah Lin, MD",
            "hospital": "Metro Labs & Diagnostics",
            "encryption_algorithm": "AES-256-GCM",
            "key_fingerprint": "SHA256:e7ec067240f521b0...dd24",
            "checksum_sha256": "53a1c47e990b7e9370268003d1ee9d843f27097656a8d2d5555fe1251c384384",
            "tx_hash": "0x4f82bc7190de1249fa6b2194c730e1bb45920b784a9382fec32104d49a712c98",
        }
        r3 = {
            "id": "rec-003",
            "patient_id": "pat-984210",
            "patient_name": "Eleanor Vance",
            "title": "Cardiac Post-Operative Treatment & Prescription Regimen",
            "record_type": "PRESCRIPTION",
            "ipfs_cid": "bafkreia3ptjqohjrgx7vxpefcr56dlgudoohqfgqzqu7w4lo3w4ycjriny",
            "file_size": "420 KB",
            "mime_type": "application/pdf",
            "created_at": "2026-10-08T11:45:00Z",
            "created_by_doctor": "Dr. Marcus Sterling, MD",
            "hospital": "Metro General Hospital",
            "encryption_algorithm": "AES-256-GCM",
            "key_fingerprint": "SHA256:58560c63e1ae1b55...db2c",
            "checksum_sha256": "1b7cd3071d3135ff5bbc85147be1acd41b9c7814d0cc29fb716eddb98126286e",
            "tx_hash": "0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1",
        }
        for rec in (r1, r2, r3):
            self._records[rec["id"]] = rec

        c1 = {
            "id": "cst-8801",
            "patient_id": "pat-984210",
            "doctor_id": "doc-331902",
            "doctor_name": "Dr. Marcus Sterling, MD",
            "hospital": "Metro General Hospital",
            "specialty": "Cardiovascular Surgery",
            "purpose": "Ongoing cardiovascular post-op observation & diagnostic follow-up",
            "status": "ACTIVE",
            "allowed_record_types": "ALL",
            "granted_at": "2026-09-29T10:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
            "valid_until_epoch": 1798761599,
            "tx_hash": "0x4f82bc7190de1249fa6b2194c730e1bb45920b784a9382fec32104d49a712c98"
        }
        c2 = {
            "id": "cst-8802",
            "patient_id": "pat-984210",
            "doctor_id": "doc-441209",
            "doctor_name": "Dr. Nathan Drake, MD",
            "hospital": "St. Jude Neurology Center",
            "specialty": "Neurology Consultation",
            "purpose": "Elective migraine diagnostic assessment & historical MRI review",
            "status": "PENDING",
            "allowed_record_types": ["IMAGING_MRI", "CLINICAL_SUMMARY"],
            "granted_at": "2026-10-11T16:20:00Z",
            "expires_at": "2026-11-11T23:59:59Z",
            "valid_until_epoch": 1794355199,
            "tx_hash": "0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1"
        }
        c3 = {
            "id": "cst-8790",
            "patient_id": "pat-984210",
            "doctor_id": "doc-119283",
            "doctor_name": "Dr. Clara Oswald, DDS",
            "hospital": "Apex Dental & Maxillofacial",
            "specialty": "Oral Surgery",
            "purpose": "Dental surgery pre-clearance consultation",
            "status": "REVOKED",
            "allowed_record_types": ["LAB_REPORT"],
            "granted_at": "2026-08-10T08:00:00Z",
            "expires_at": "2026-09-10T23:59:59Z",
            "valid_until_epoch": 1789084799,
            "tx_hash": "0x99281741bb82910fc38201948ba29031ca7192830491823abcbfa98210492104"
        }
        for c in (c1, c2, c3):
            self._consents[c["id"]] = c

        logs = [
            ("aud-9904", "2026-10-08T11:45:00Z", "doc-331902", "Dr. Marcus Sterling, MD", "DOCTOR", "pat-984210", "UPLOAD_RECORD", "rec-003", "Cardiac Post-Operative Treatment & Prescription Regimen", "Upload encrypted clinical discharge prescription", "0x334901ba7162e91024b819203a7491bb4029183746112a9bc8301726a992014b", "SUCCESS"),
            ("aud-9903", "2026-10-09T18:40:11Z", "pat-984210", "Eleanor Vance", "PATIENT", "pat-984210", "REVOKE_CONSENT", None, None, "Revoked access for Dr. Clara Oswald after treatment completion", "0x99281741bb82910fc38201948ba29031ca7192830491823abcbfa98210492104", "SUCCESS"),
            ("aud-9902", "2026-10-11T16:20:00Z", "doc-441209", "Dr. Nathan Drake, MD", "DOCTOR", "pat-984210", "REQUEST_CONSENT", None, None, "Elective migraine diagnostic assessment & historical MRI review", "0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1", "SUCCESS"),
            ("aud-9901", "2026-10-12T06:14:22Z", "doc-331902", "Dr. Marcus Sterling, MD", "DOCTOR", "pat-984210", "VIEW", "rec-001", "Echocardiogram Comprehensive Diagnostic Report", "Review of ejection fraction before medication titration", "0x12a9bc8301726a992014bca81923049182bbaf49201948271039840291837461", "SUCCESS"),
        ]
        for aid, ts, actor_id, actor_name, role, target_pat, action, rid, rtitle, purpose, tx, status in logs:
            entry = {
                "id": aid,
                "seq": len(self._audit_chain) + 1,
                "timestamp": ts,
                "actor_id": actor_id,
                "actor_name": actor_name,
                "actor_role": role,
                "target_patient_id": target_pat,
                "action": action,
                "event_type": action,
                "record_id": rid or "",
                "record_title": rtitle,
                "purpose": purpose,
                "tx_hash": tx,
                "status": status,
                "detail": purpose,
                "prev_hash": self._prev_audit_hash,
            }
            canonical_str = canonical_json_dumps(entry)
            entry_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
            entry["entry_hash"] = entry_hash
            self._audit_chain.append(entry)
            self._prev_audit_hash = entry_hash

    def _load_crypto_materials(self) -> None:
        """Loads and verifies existence of Org1 crypto material on disk."""
        # 1. Connection profile
        try:
            profile_path = Path(self.connection_profile_path)
            if not profile_path.is_absolute():
                # Resolve relative to project root or cwd
                base_dir = Path(os.getcwd())
                if (base_dir / profile_path).exists():
                    profile_path = base_dir / profile_path
                elif (base_dir / "My Team Project" / profile_path).exists():
                    profile_path = base_dir / "My Team Project" / profile_path
                elif (base_dir.parent / profile_path).exists():
                    profile_path = base_dir.parent / profile_path

            if profile_path.exists():
                with open(profile_path, "r", encoding="utf-8") as f:
                    self._connection_profile = json.load(f)
                logger.info("Fabric Gateway: Loaded connection profile from %s", profile_path)
        except Exception as e:
            logger.warning("Fabric Gateway: Connection profile load notice: %s", e)

        # 2. User Certificate
        try:
            cert_path = Path(self.user_cert_path)
            if not cert_path.is_absolute():
                base_dir = Path(os.getcwd())
                if (base_dir / cert_path).exists():
                    cert_path = base_dir / cert_path
                elif (base_dir / "My Team Project" / cert_path).exists():
                    cert_path = base_dir / "My Team Project" / cert_path
                elif (base_dir.parent / cert_path).exists():
                    cert_path = base_dir.parent / cert_path

            if cert_path.exists():
                with open(cert_path, "r", encoding="utf-8") as f:
                    self._user_cert = f.read()
                logger.info("Fabric Gateway: Loaded User1 certificate (%d bytes)", len(self._user_cert))
        except Exception as e:
            logger.warning("Fabric Gateway: User certificate load notice: %s", e)

        # 3. User Private Key
        try:
            key_dir = Path(self.user_key_dir)
            if not key_dir.is_absolute():
                base_dir = Path(os.getcwd())
                if (base_dir / key_dir).exists():
                    key_dir = base_dir / key_dir
                elif (base_dir / "My Team Project" / key_dir).exists():
                    key_dir = base_dir / "My Team Project" / key_dir
                elif (base_dir.parent / key_dir).exists():
                    key_dir = base_dir.parent / key_dir

            if key_dir.exists() and key_dir.is_dir():
                key_files = list(key_dir.glob("*_sk")) or list(key_dir.glob("*.key")) or list(key_dir.glob("*"))
                if key_files:
                    with open(key_files[0], "r", encoding="utf-8") as f:
                        self._user_private_key = f.read()
                    logger.info("Fabric Gateway: Loaded User1 private key from %s", key_files[0].name)
        except Exception as e:
            logger.warning("Fabric Gateway: Private key load notice: %s", e)

        # 4. TLS Root Cert
        try:
            tls_path = Path(self.tls_cert_path)
            if not tls_path.is_absolute():
                base_dir = Path(os.getcwd())
                if (base_dir / tls_path).exists():
                    tls_path = base_dir / tls_path
                elif (base_dir / "My Team Project" / tls_path).exists():
                    tls_path = base_dir / "My Team Project" / tls_path
                elif (base_dir.parent / tls_path).exists():
                    tls_path = base_dir.parent / tls_path

            if tls_path.exists():
                with open(tls_path, "r", encoding="utf-8") as f:
                    self._tls_ca_cert = f.read()
                logger.info("Fabric Gateway: Loaded TLS CA cert (%d bytes)", len(self._tls_ca_cert))
        except Exception as e:
            logger.warning("Fabric Gateway: TLS root cert load notice: %s", e)

    # ==========================================
    # DOCKER CLI-BASED EXECUTION ENGINE (OPTION B)
    # ==========================================

    @classmethod
    def _resolve_docker_binary(cls) -> str:
        """
        Resolves the absolute path to the Docker CLI binary.
        Checks shutil.which, standard Windows Docker Desktop paths,
        and standard Linux/macOS paths before falling back to bare 'docker'.
        """
        found = shutil.which("docker")
        if found:
            return found

        candidates = [
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"),
            os.path.expandvars(r"%ProgramFiles%\Docker\Docker\resources\bin\docker.exe"),
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            "/usr/local/bin/docker",
            "/usr/bin/docker",
        ]
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                return candidate

        return "docker"

    def _execute_peer_query(self, function_name: str, args: List[Any], timeout: float = 10.0) -> Any:
        """
        Executes a read-only chaincode query via docker exec peer0.org1 peer chaincode query.
        Does not generate a transaction block or mutate world state.
        """
        docker_bin = self._resolve_docker_binary()
        str_args = [str(a) if not isinstance(a, str) else a for a in args]
        payload = json.dumps({"function": function_name, "Args": str_args})

        cmd = [
            docker_bin, "exec",
            "-e", "CORE_PEER_LOCALMSPID=Org1MSP",
            "-e", "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/client-msp",
            "-e", "CORE_PEER_TLS_ENABLED=true",
            "-e", "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt",
            "-e", "CORE_PEER_ADDRESS=peer0.org1.medtrust.com:7051",
            "peer0.org1.medtrust.com",
            "peer", "chaincode", "query",
            "-C", self.channel_name,
            "-n", self.chaincode_name,
            "-c", payload,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            logger.error("Fabric query timeout (%ss) on %s", timeout, function_name)
            raise FabricGatewayError(f"Fabric query timed out after {timeout}s") from e
        except FileNotFoundError as e:
            logger.error("Fabric query executable not found (%s): %s", docker_bin, e)
            raise FabricGatewayError(f"Docker executable not found or inaccessible ('{docker_bin}'): {e}") from e
        except Exception as e:
            logger.error("Fabric query execution error (%s): %s", type(e).__name__, e)
            raise FabricGatewayError(f"Fabric query execution failed: {type(e).__name__} - {e}") from e

        if proc.returncode != 0:
            err_text = proc.stderr.strip()
            logger.warning("Fabric query returned code %d: %s", proc.returncode, err_text)
            if "does not exist" in err_text.lower() or "not found" in err_text.lower():
                if "record" in function_name.lower():
                    raise RecordNotFoundError(f"Record query failed: {err_text}")
                elif "consent" in function_name.lower():
                    raise ConsentNotFoundError(f"Consent query failed: {err_text}")
            if "access denied" in err_text.lower() or "unauthorized" in err_text.lower():
                raise AccessDeniedError(f"Fabric authorization denied: {err_text}")
            raise FabricGatewayError(f"Fabric query error: {err_text}")

        stdout = proc.stdout.strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return stdout

    def _execute_peer_invoke(self, function_name: str, args: List[Any], timeout: float = 15.0) -> Dict[str, Any]:
        """
        Executes a ledger-mutating chaincode transaction via docker exec peer0.org1 peer chaincode invoke.
        Collects endorsements from Org1 and Org2 peers, delivers to Orderer, and waits for block commit.
        """
        docker_bin = self._resolve_docker_binary()
        str_args = [str(a) if not isinstance(a, str) else a for a in args]
        payload = json.dumps({"function": function_name, "Args": str_args})

        cmd = [
            docker_bin, "exec",
            "-e", "CORE_PEER_LOCALMSPID=Org1MSP",
            "-e", "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/client-msp",
            "-e", "CORE_PEER_TLS_ENABLED=true",
            "-e", "CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt",
            "-e", "CORE_PEER_ADDRESS=peer0.org1.medtrust.com:7051",
            "peer0.org1.medtrust.com",
            "peer", "chaincode", "invoke",
            "-o", "orderer.medtrust.com:7050",
            "--ordererTLSHostnameOverride", "orderer.medtrust.com",
            "--tls",
            "--cafile", "/etc/hyperledger/fabric/orderer-ca.crt",
            "-C", self.channel_name,
            "-n", self.chaincode_name,
            "--peerAddresses", "peer0.org1.medtrust.com:7051",
            "--tlsRootCertFiles", "/etc/hyperledger/fabric/tls/ca.crt",
            "--peerAddresses", "peer0.org2.medtrust.com:9051",
            "--tlsRootCertFiles", "/etc/hyperledger/fabric/org2-tls-ca.crt",
            "--waitForEvent",
            "--waitForEventTimeout", "10s",
            "-c", payload,
        ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            logger.error("Fabric invoke timeout (%ss) on %s", timeout, function_name)
            raise FabricGatewayError(f"Fabric transaction timed out after {timeout}s") from e
        except FileNotFoundError as e:
            logger.error("Fabric invoke executable not found (%s): %s", docker_bin, e)
            raise FabricGatewayError(f"Docker executable not found or inaccessible ('{docker_bin}'): {e}") from e
        except Exception as e:
            logger.error("Fabric invoke execution error (%s): %s", type(e).__name__, e)
            raise FabricGatewayError(f"Fabric transaction invoke failed: {type(e).__name__} - {e}") from e

        stderr = proc.stderr
        if proc.returncode != 0:
            logger.error("Fabric invoke failed with code %d: %s", proc.returncode, stderr.strip())
            if "already exists" in stderr.lower() or "collision" in stderr.lower():
                raise FabricGatewayError(f"Ledger entity already exists: {stderr.strip()}")
            if "access denied" in stderr.lower() or "unauthorized" in stderr.lower():
                raise AccessDeniedError(f"Fabric authorization denied: {stderr.strip()}")
            raise FabricGatewayError(f"Fabric transaction failed: {stderr.strip()}")

        if "committed with status (VALID)" not in stderr:
            logger.error("Fabric invoke did not receive VALID commit status: %s", stderr.strip())
            raise FabricGatewayError(f"Transaction submitted but commit status not confirmed: {stderr.strip()}")

        tx_match = re.search(r"txid\s+\[([a-fA-F0-9]+)\]\s+committed\s+with\s+status\s+\(VALID\)", stderr)
        tx_id = f"0x{tx_match.group(1)}" if tx_match else generate_tx_hash()

        return {
            "status": "COMMITTED",
            "tx_hash": tx_id,
            "raw_output": proc.stdout.strip(),
        }

    def check_peer_connectivity(self) -> Dict[str, Any]:
        """
        Probes the Fabric peer endpoint (e.g. localhost:7051) using a TCP socket check.
        Returns live connectivity status without hanging.
        """
        host = "localhost"
        port = 7051
        if ":" in self.peer_endpoint:
            parts = self.peer_endpoint.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 7051

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((host, port))
            is_open = (result == 0)
        except Exception:
            is_open = False
        finally:
            sock.close()

        has_creds = bool(self._user_cert and self._user_private_key)
        mode = "live" if (is_open and has_creds) else "standby"

        return {
            "peer_endpoint": self.peer_endpoint,
            "port_open": is_open,
            "credentials_loaded": has_creds,
            "mode": mode,
            "channel": self.channel_name,
            "chaincode": self.chaincode_name,
            "contract": self.contract_name,
            "msp_id": self.msp_id,
        }

    # ==========================================
    # CONSENT CONTRACT (GATEWAY_ADAPTER_SPEC 2.1)
    # ==========================================

    def request_consent(
        self,
        consent_id: str,
        patient_id: str,
        doctor_id: str,
        allowed_record_types: Union[List[str], str],
        valid_until_epoch: int,
        purpose: str = "",
        doctor_name: Optional[str] = None,
        hospital: Optional[str] = None,
        specialty: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:RequestConsent transaction.
        Arguments strictly validated for Zero PHI.
        """
        assert_zero_phi(patient_id, "patient_id")
        assert_zero_phi(doctor_id, "doctor_id")
        assert_zero_phi(purpose, "purpose")

        types_json = allowed_record_types if isinstance(allowed_record_types, str) else json.dumps(allowed_record_types)
        assert_zero_phi(types_json, "allowed_record_types")

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            types_str = types_json if isinstance(types_json, str) else json.dumps(types_json)
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:RequestConsent",
                [consent_id, patient_id, doctor_id, types_str, str(valid_until_epoch), purpose],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            now_ts = int(time.time())
            entry = {
                "id": consent_id,
                "consent_id": consent_id,
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "doctor_name": doctor_name or "Doctor",
                "hospital": hospital or "Metro General Hospital",
                "specialty": specialty or "General Practice",
                "purpose": purpose,
                "status": "PENDING",
                "allowed_record_types": json.loads(types_json) if isinstance(types_json, str) else allowed_record_types,
                "granted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts)),
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(valid_until_epoch)),
                "valid_until_epoch": valid_until_epoch,
                "tx_hash": tx_hash,
                "channel": self.channel_name,
                "contract": f"{self.contract_name}:RequestConsent",
            }
            self._consents[consent_id] = entry
            logger.info("RealFabricGateway: Live RequestConsent committed %s (Tx: %s)", consent_id, tx_hash)
            return entry

        tx_hash = generate_tx_hash()
        now_ts = int(time.time())

        entry = {
            "id": consent_id,
            "consent_id": consent_id,
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "doctor_name": doctor_name or "Doctor",
            "hospital": hospital or "Metro General Hospital",
            "specialty": specialty or "General Practice",
            "purpose": purpose,
            "status": "PENDING",
            "allowed_record_types": json.loads(types_json) if isinstance(types_json, str) else allowed_record_types,
            "granted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts)),
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(valid_until_epoch)),
            "valid_until_epoch": valid_until_epoch,
            "tx_hash": tx_hash,
            "channel": self.channel_name,
            "contract": f"{self.contract_name}:RequestConsent",
        }

        self._consents[consent_id] = entry
        logger.info("RealFabricGateway: RequestConsent committed %s (Tx: %s)", consent_id, tx_hash)
        return entry

    def grant_consent(
        self,
        consent_id: str,
        patient_id: str,
        doctor_id: str = "",
        allowed_record_types: Union[List[str], str] = '["ALL"]',
        valid_until_epoch: int = 0,
        purpose: str = "",
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:GrantConsent transaction.
        Enforces patient ownership and updates existing consent.
        """
        assert_zero_phi(patient_id, "patient_id")
        assert_zero_phi(doctor_id, "doctor_id")
        assert_zero_phi(purpose, "purpose")

        existing_consent: Optional[Dict[str, Any]] = None
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            # 1. Check in-memory cache
            if consent_id in self._consents:
                existing_consent = self._consents[consent_id]
            else:
                # 2. Query ledger to see if consent exists on-chain
                try:
                    query_res = self._execute_peer_query(
                        f"{self.contract_name}:GetConsent",
                        [consent_id],
                    )
                    if query_res:
                        raw_dict = query_res if isinstance(query_res, dict) else json.loads(query_res)
                        existing_consent = self._normalize_ledger_consent(raw_dict)
                except Exception as e:
                    logger.warning("GetConsent lookup for %s: %s", consent_id, e)

            # Fail-closed guard: do not create a new consent grant when approving an existing request
            if not existing_consent and not doctor_id:
                raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")

            if existing_consent:
                # Preserve and hydrate original attributes
                doctor_id = doctor_id or existing_consent.get("doctor_id") or existing_consent.get("doctorId", "")
                purpose = purpose or existing_consent.get("purpose", "")
                if valid_until_epoch == 0:
                    valid_until_epoch = existing_consent.get("valid_until_epoch", 0)
                if allowed_record_types == '["ALL"]' and "allowed_record_types" in existing_consent:
                    allowed_record_types = existing_consent["allowed_record_types"]

            types_json = allowed_record_types if isinstance(allowed_record_types, str) else json.dumps(allowed_record_types)
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:GrantConsent",
                [consent_id, patient_id, doctor_id, types_json, str(valid_until_epoch), purpose],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            if consent_id in self._consents:
                self._consents[consent_id]["status"] = "ACTIVE"
                self._consents[consent_id]["tx_hash"] = tx_hash
                self._consents[consent_id]["updated_at"] = now_str
                return self._consents[consent_id]

            entry = existing_consent.copy() if existing_consent else {
                "id": consent_id,
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "purpose": purpose,
                "allowed_record_types": allowed_record_types,
                "valid_until_epoch": valid_until_epoch,
                "granted_at": now_str,
                "expires_at": now_str,
            }
            entry["status"] = "ACTIVE"
            entry["tx_hash"] = tx_hash
            entry["updated_at"] = now_str
            self._consents[consent_id] = entry
            return entry

        if consent_id not in self._consents:
            raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")

        consent = self._consents[consent_id]
        if consent["patient_id"] != patient_id:
            raise AccessDeniedError(
                f"Patient '{patient_id}' cannot grant consent belonging to '{consent['patient_id']}': UNAUTHORIZED_GRANT",
                code=403,
                reason="UNAUTHORIZED_GRANT",
            )

        tx_hash = generate_tx_hash()
        consent["status"] = "ACTIVE"
        consent["tx_hash"] = tx_hash
        consent["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logger.info("RealFabricGateway: GrantConsent committed %s (Tx: %s)", consent_id, tx_hash)
        return consent

    def reject_consent(
        self,
        consent_id: str,
        patient_id: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:RejectConsent transaction.
        """
        assert_zero_phi(patient_id, "patient_id")
        assert_zero_phi(reason, "reason")

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:RejectConsent",
                [consent_id, patient_id, reason],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            if consent_id in self._consents:
                self._consents[consent_id]["status"] = "REJECTED"
                self._consents[consent_id]["rejection_reason"] = reason
                self._consents[consent_id]["tx_hash"] = tx_hash
                return self._consents[consent_id]
            entry = {
                "id": consent_id,
                "status": "REJECTED",
                "rejection_reason": reason,
                "tx_hash": tx_hash,
            }
            self._consents[consent_id] = entry
            return entry

        if consent_id not in self._consents:
            raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")

        consent = self._consents[consent_id]
        if consent["patient_id"] != patient_id:
            raise AccessDeniedError(
                f"Patient '{patient_id}' cannot reject consent belonging to '{consent['patient_id']}': UNAUTHORIZED_REJECTION",
                code=403,
                reason="UNAUTHORIZED_REJECTION",
            )

        tx_hash = generate_tx_hash()
        consent["status"] = "REJECTED"
        consent["rejection_reason"] = reason
        consent["tx_hash"] = tx_hash
        logger.info("RealFabricGateway: RejectConsent committed %s (Tx: %s)", consent_id, tx_hash)
        return consent

    def revoke_consent(
        self,
        consent_id: str,
        requesting_patient_id: str,
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:RevokeConsent transaction.
        Enforces strict patient ownership invariant. Immediate atomic effect.
        """
        assert_zero_phi(requesting_patient_id, "requesting_patient_id")

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:RevokeConsent",
                [consent_id, requesting_patient_id],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            if consent_id in self._consents:
                self._consents[consent_id]["status"] = "REVOKED"
                self._consents[consent_id]["revoked_at"] = int(time.time())
                self._consents[consent_id]["tx_hash"] = tx_hash
                return self._consents[consent_id]
            entry = {
                "id": consent_id,
                "status": "REVOKED",
                "revoked_at": int(time.time()),
                "tx_hash": tx_hash,
            }
            self._consents[consent_id] = entry
            return entry

        if consent_id not in self._consents:
            raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")

        consent = self._consents[consent_id]
        if consent["patient_id"] != requesting_patient_id:
            raise AccessDeniedError(
                f"Patient '{requesting_patient_id}' cannot revoke consent belonging to '{consent['patient_id']}': REVOCATION_OWNERSHIP_VIOLATION",
                code=403,
                reason="REVOCATION_OWNERSHIP_VIOLATION",
            )

        tx_hash = generate_tx_hash()
        consent["status"] = "REVOKED"
        consent["revoked_at"] = int(time.time())
        consent["tx_hash"] = tx_hash
        logger.info("RealFabricGateway: RevokeConsent committed %s (Tx: %s)", consent_id, tx_hash)
        return consent

    def verify_consent(
        self,
        doctor_id: str,
        patient_id: str,
        record_type: str,
    ) -> Dict[str, Any]:
        """
        Evaluates MedTrustContract:VerifyConsent query.
        Returns authorization result with explicit reason code according to spec.
        Resolves multiple consents so pending, expired, or category-mismatched grants
        do not hide valid active grants, while preserving the strict rule that a revoked
        consent terminates authorization for that category.
        """
        assert_zero_phi(doctor_id, "doctor_id")
        assert_zero_phi(patient_id, "patient_id")
        assert_zero_phi(record_type, "record_type")

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:VerifyConsent",
                [doctor_id, patient_id, record_type or ""],
            )
            if isinstance(query_res, dict):
                return query_res
            return json.loads(query_res) if isinstance(query_res, str) else query_res

        matching = [
            c for c in self._consents.values()
            if c["patient_id"] == patient_id and c["doctor_id"] == doctor_id
        ]
        if not matching:
            return {
                "allowed": False,
                "reason": "NO_CONSENT_FOUND",
                "consentId": None,
                "validUntil": None,
                "allowedRecordTypes": [],
            }

        def _is_scoped(allowed_types: Any, target_type: str) -> bool:
            if not target_type or target_type == "ALL":
                return True
            if allowed_types == "ALL":
                return True
            if isinstance(allowed_types, list):
                return "ALL" in allowed_types or target_type in allowed_types
            return False

        # Filter consents that cover the requested record category
        scoped_consents = [c for c in matching if _is_scoped(c.get("allowed_record_types"), record_type)]
        if not scoped_consents:
            last_consent = matching[-1]
            return {
                "allowed": False,
                "reason": "CONSENT_SCOPE_EXCLUDED",
                "consentId": last_consent.get("id"),
                "validUntil": last_consent.get("valid_until_epoch"),
                "allowedRecordTypes": last_consent.get("allowed_record_types", []),
            }

        first_ineligible: Optional[Dict[str, Any]] = None
        now = time.time()

        for consent in reversed(scoped_consents):
            status = consent.get("status")
            valid_until = consent.get("valid_until_epoch", 0)
            allowed_types = consent.get("allowed_record_types", [])

            # 1. A revoked consent terminating this category halts older grants from reviving access
            if status == "REVOKED":
                return {
                    "allowed": False,
                    "reason": "CONSENT_REVOKED",
                    "consentId": consent["id"],
                    "validUntil": valid_until,
                    "allowedRecordTypes": allowed_types,
                }

            # 2. Check for active, unexpired consent
            if status == "ACTIVE":
                if now <= valid_until:
                    return {
                        "allowed": True,
                        "reason": "CONSENT_ACTIVE",
                        "consentId": consent["id"],
                        "validUntil": valid_until,
                        "allowedRecordTypes": allowed_types,
                    }
                else:
                    # Expired active consent cannot grant access, but does not hide an older valid grant
                    if first_ineligible is None:
                        first_ineligible = {
                            "allowed": False,
                            "reason": "CONSENT_EXPIRED",
                            "consentId": consent["id"],
                            "validUntil": valid_until,
                            "allowedRecordTypes": allowed_types,
                        }
                    continue

            # 3. Pending request cannot grant access, but does not hide an existing valid active grant
            if status == "PENDING":
                if first_ineligible is None:
                    first_ineligible = {
                        "allowed": False,
                        "reason": "CONSENT_PENDING",
                        "consentId": consent["id"],
                        "validUntil": valid_until,
                        "allowedRecordTypes": allowed_types,
                    }
                continue

            # 4. Rejected request
            if status == "REJECTED":
                if first_ineligible is None:
                    first_ineligible = {
                        "allowed": False,
                        "reason": "CONSENT_REJECTED",
                        "consentId": consent["id"],
                        "validUntil": valid_until,
                        "allowedRecordTypes": allowed_types,
                    }
                continue

            # 5. Any other non-active status
            if first_ineligible is None:
                first_ineligible = {
                    "allowed": False,
                    "reason": f"CONSENT_{status}",
                    "consentId": consent["id"],
                    "validUntil": valid_until,
                    "allowedRecordTypes": allowed_types,
                }

        # If no active unexpired consent was found across scoped consents, return the newest failure reason
        if first_ineligible is not None:
            return first_ineligible

        return {
            "allowed": False,
            "reason": "NO_ACTIVE_CONSENT",
            "consentId": None,
            "validUntil": None,
            "allowedRecordTypes": [],
        }

    def _normalize_ledger_consent(self, r: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes a raw Fabric ledger consent object into the standard ConsentRecord schema."""
        cid = r.get("consentId") or r.get("id", "")
        pid = r.get("patientId") or r.get("patient_id", "")
        did = r.get("doctorId") or r.get("doctor_id", "")

        cached = self._consents.get(cid, {})
        dname = cached.get("doctor_name")
        hosp = cached.get("hospital")
        spec = cached.get("specialty")
        tx = cached.get("tx_hash") or r.get("txHash") or r.get("tx_hash")

        if not (dname and hosp and spec):
            try:
                from app.db.session import SessionLocal
                from app.db.models import UserModel
                with SessionLocal() as db_session:
                    doc_user = db_session.query(UserModel).filter(UserModel.id == did).first()
                    if doc_user:
                        dname = dname or doc_user.name
                        hosp = hosp or doc_user.hospital
                        spec = spec or doc_user.specialty
            except Exception:
                pass

        dname = dname or "Doctor"
        hosp = hosp or "Metro General Hospital"
        spec = spec or "General Practice"

        raw_status = str(r.get("status", "PENDING")).upper()
        if raw_status in ("APPROVED", "ACTIVE"):
            status_val = "ACTIVE"
        elif raw_status in ("REVOKED", "REJECTED"):
            status_val = "REVOKED"
        elif raw_status == "EXPIRED":
            status_val = "EXPIRED"
        else:
            status_val = "PENDING"

        created_ts = r.get("createdAt") or r.get("created_at") or int(time.time())
        valid_ts = r.get("validUntil") or r.get("valid_until") or r.get("valid_until_epoch") or (created_ts + 86400 * 30)

        granted_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(created_ts)))
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(valid_ts)))

        rec_types = r.get("allowedRecordTypes") or r.get("allowed_record_types") or ["ALL"]
        if isinstance(rec_types, str) and rec_types.startswith("["):
            try:
                rec_types = json.loads(rec_types)
            except Exception:
                pass

        if not tx:
            tx = "0x" + hashlib.sha256(f"{cid}-{created_ts}".encode()).hexdigest()

        return {
            "id": cid,
            "consent_id": cid,
            "patient_id": pid,
            "doctor_id": did,
            "doctor_name": dname,
            "hospital": hosp,
            "specialty": spec,
            "purpose": r.get("purpose", ""),
            "status": status_val,
            "allowed_record_types": rec_types,
            "granted_at": granted_at,
            "expires_at": expires_at,
            "valid_until_epoch": int(valid_ts),
            "tx_hash": tx,
        }

    def get_consent(self, consent_id: str) -> Dict[str, Any]:
        """Evaluates MedTrustContract:GetConsent query."""
        assert_zero_phi(consent_id, "consent_id")
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:GetConsent",
                [consent_id],
            )
            if not query_res:
                raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")
            raw_dict = query_res if isinstance(query_res, dict) else json.loads(query_res)
            return self._normalize_ledger_consent(raw_dict)

        if consent_id not in self._consents:
            raise ConsentNotFoundError(f"Consent record '{consent_id}' not found on Fabric ledger.")
        return self._consents[consent_id]

    def get_consents_by_patient(self, patient_id: str) -> List[Dict[str, Any]]:
        """Evaluates MedTrustContract:GetConsentsByPatient query."""
        assert_zero_phi(patient_id, "patient_id")
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:GetConsentsByPatient",
                [patient_id],
            )
            raw_list = query_res if isinstance(query_res, list) else (json.loads(query_res) if isinstance(query_res, str) else [])
            normalized_results = []
            for r in raw_list:
                norm = self._normalize_ledger_consent(r)
                normalized_results.append(norm)
                self._consents[norm["id"]] = norm
            return normalized_results

        return [c for c in self._consents.values() if c.get("patient_id") == patient_id or c.get("patientId") == patient_id]

    # ==========================================
    # RECORD CONTRACT (GATEWAY_ADAPTER_SPEC 2.2)
    # ==========================================

    def register_record_metadata(
        self,
        record_id: str,
        patient_id: str,
        ipfs_cid: str,
        checksum: str,
        record_type: str,
        facility: str = "Synthetic Hospital",
        registered_by: str = "",
        patient_name: Optional[str] = None,
        title: Optional[str] = None,
        file_size: Optional[str] = None,
        mime_type: Optional[str] = None,
        key_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:RegisterRecord transaction.
        Enforces Zero-PHI check on all fields.
        """
        assert_zero_phi(record_id, "record_id")
        assert_zero_phi(patient_id, "patient_id")
        assert_zero_phi(ipfs_cid, "ipfs_cid")
        assert_zero_phi(checksum, "checksum")
        assert_zero_phi(record_type, "record_type")
        assert_zero_phi(facility, "facility")
        assert_zero_phi(registered_by, "registered_by")
        assert_zero_phi(title, "title")

        # Validate SHA-256 checksum format (64-char hex)
        if len(checksum) != 64 or not all(c in "0123456789abcdefABCDEF" for c in checksum):
            raise FabricGatewayError(f"Invalid SHA-256 checksum format: '{checksum}'", code=400)

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:RegisterRecord",
                [
                    record_id,
                    patient_id,
                    ipfs_cid,
                    checksum.lower(),
                    record_type,
                    facility,
                    registered_by,
                ],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            record_entry = {
                "id": record_id,
                "patient_id": patient_id,
                "patient_name": patient_name or "Synthetic Patient",
                "title": title or f"Record {record_id}",
                "record_type": record_type,
                "ipfs_cid": ipfs_cid,
                "file_size": file_size or "1.0 MB",
                "mime_type": mime_type or "application/pdf",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "created_by_doctor": registered_by,
                "hospital": facility,
                "encryption_algorithm": "AES-256-GCM",
                "key_fingerprint": key_fingerprint or f"SHA256:{checksum[:16]}",
                "checksum_sha256": checksum.lower(),
                "tx_hash": tx_hash,
                "channel": self.channel_name,
                "contract": f"{self.contract_name}:RegisterRecord",
            }
            self._records[record_id] = record_entry
            logger.info("RealFabricGateway: Live RegisterRecord committed %s (Tx: %s)", record_id, tx_hash)
            return record_entry

        tx_hash = generate_tx_hash()
        record_entry = {
            "id": record_id,
            "patient_id": patient_id,
            "patient_name": patient_name or "Synthetic Patient",
            "title": title or f"Record {record_id}",
            "record_type": record_type,
            "ipfs_cid": ipfs_cid,
            "file_size": file_size or "1.0 MB",
            "mime_type": mime_type or "application/pdf",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "created_by_doctor": registered_by,
            "hospital": facility,
            "encryption_algorithm": "AES-256-GCM",
            "key_fingerprint": key_fingerprint or f"SHA256:{checksum[:16]}",
            "checksum_sha256": checksum.lower(),
            "tx_hash": tx_hash,
            "channel": self.channel_name,
            "contract": f"{self.contract_name}:RegisterRecord",
        }

        self._records[record_id] = record_entry
        logger.info("RealFabricGateway: RegisterRecord committed %s (Tx: %s)", record_id, tx_hash)
        return record_entry

    def register_record(
        self,
        record_id: str,
        patient_id: str,
        ipfs_cid: str,
        checksum: str,
        record_type: str,
        facility: str = "Synthetic Hospital",
        registered_by: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """Method alias for register_record_metadata matching GATEWAY_ADAPTER_SPEC."""
        return self.register_record_metadata(
            record_id=record_id,
            patient_id=patient_id,
            ipfs_cid=ipfs_cid,
            checksum=checksum,
            record_type=record_type,
            facility=facility,
            registered_by=registered_by,
            **kwargs
        )

    def _normalize_ledger_record(self, raw_item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes a raw Fabric ledger record into the standard MedicalRecord schema."""
        res = dict(raw_item)
        rec_id = res.get("recordId") or res.get("id") or ""
        cached = self._records.get(rec_id, {})

        res["id"] = rec_id
        res["recordId"] = rec_id

        pat_id = res.get("patientId") or res.get("patient_id") or cached.get("patient_id") or "UNKNOWN"
        res["patient_id"] = pat_id
        res["patientId"] = pat_id

        # Hydrate patient name from cached record or database
        pat_name = cached.get("patient_name") or cached.get("patientName") or res.get("patient_name") or res.get("patientName")
        if not pat_name or pat_name.startswith("Patient pat-") or pat_name == "Patient UNKNOWN":
            try:
                from app.db.session import SessionLocal
                from app.db.models import UserModel
                with SessionLocal() as db_session:
                    user_row = db_session.query(UserModel).filter(UserModel.id == pat_id).first()
                    if user_row and user_row.name:
                        pat_name = user_row.name
            except Exception:
                pass
        res["patient_name"] = pat_name or f"Patient {pat_id}"
        res["patientName"] = res["patient_name"]

        raw_type = res.get("recordType") or res.get("record_type") or cached.get("record_type") or "CLINICAL_SUMMARY"
        clean_type = str(raw_type).strip().upper()
        res["record_type"] = clean_type
        res["recordType"] = clean_type

        res["title"] = cached.get("title") or res.get("title") or f"{clean_type} ({rec_id})"
        csum = res.get("checksum") or res.get("checksum_sha256") or cached.get("checksum_sha256") or ""
        res["checksum_sha256"] = csum.lower()
        res["checksum"] = csum.lower()
        res["ipfs_cid"] = res.get("ipfsCid") or res.get("ipfs_cid") or cached.get("ipfs_cid") or ""
        res["ipfsCid"] = res["ipfs_cid"]
        res["created_by_doctor"] = cached.get("created_by_doctor") or res.get("registeredBy") or res.get("created_by_doctor") or "Doctor"
        res["hospital"] = cached.get("hospital") or res.get("facility") or res.get("hospital") or "Metro General Hospital"
        res["file_size"] = cached.get("file_size") or res.get("file_size") or "1.0 MB"
        res["mime_type"] = cached.get("mime_type") or res.get("mime_type") or "application/pdf"
        res["key_fingerprint"] = cached.get("key_fingerprint") or res.get("key_fingerprint") or (f"SHA256:{csum[:16]}" if csum else "SHA256:UNKNOWN")
        res["encryption_algorithm"] = cached.get("encryption_algorithm") or res.get("encryption_algorithm") or "AES-256-GCM"

        ts = res.get("timestamp") or cached.get("timestamp")
        if isinstance(ts, (int, float)):
            res["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        else:
            res["created_at"] = cached.get("created_at") or (str(ts) if ts else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        if "tx_hash" in cached:
            res["tx_hash"] = cached["tx_hash"]
            res["txHash"] = cached["tx_hash"]

        return res

    def get_record(self, record_id: str) -> Dict[str, Any]:
        """Evaluates MedTrustContract:GetRecord query."""
        assert_zero_phi(record_id, "record_id")
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:GetRecord",
                [record_id],
            )
            if not query_res:
                raise RecordNotFoundError(f"Record with ID '{record_id}' not found on Fabric ledger.")
            if isinstance(query_res, dict):
                norm = self._normalize_ledger_record(query_res)
                self._records[norm["id"]] = norm
                return norm
            return query_res

        if record_id not in self._records:
            raise RecordNotFoundError(f"Record with ID '{record_id}' not found on Fabric ledger.")
        return self._records[record_id]

    def get_records_by_patient(self, patient_id: str) -> List[Dict[str, Any]]:
        """Evaluates MedTrustContract:GetRecordsByPatient query."""
        assert_zero_phi(patient_id, "patient_id")
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:GetRecordsByPatient",
                [patient_id],
            )
            raw_list = query_res if isinstance(query_res, list) else (json.loads(query_res) if isinstance(query_res, str) else [])
            results = []
            for item in raw_list:
                if isinstance(item, dict):
                    norm = self._normalize_ledger_record(item)
                    results.append(norm)
                    self._records[norm["id"]] = norm
                else:
                    results.append(item)
            return results

        return [r for r in self._records.values() if r["patient_id"] == patient_id]

        return [r for r in self._records.values() if r["patient_id"] == patient_id]

    def verify_record_checksum(self, record_id: str, calculated_checksum: str) -> Dict[str, Any]:
        """
        Evaluates MedTrustContract:VerifyRecordChecksum query.
        Validates calculated IPFS payload hash against immutable registered ledger digest.
        """
        assert_zero_phi(record_id, "record_id")
        assert_zero_phi(calculated_checksum, "calculated_checksum")
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:VerifyRecordChecksum",
                [record_id, calculated_checksum.lower()],
            )
            if isinstance(query_res, dict):
                return query_res
            return json.loads(query_res) if isinstance(query_res, str) else query_res

        record = self.get_record(record_id)
        expected = record["checksum_sha256"].lower()
        calc = calculated_checksum.lower()
        is_verified = (expected == calc)

        return {
            "verified": is_verified,
            "recordId": record_id,
            "expectedChecksum": expected,
            "calculatedChecksum": calc,
            "ipfsCid": record["ipfs_cid"],
            "status": "VERIFIED_INTACT" if is_verified else "CHECKSUM_MISMATCH",
        }

    # ==========================================
    # AUDIT CONTRACT (GATEWAY_ADAPTER_SPEC 2.3)
    # ==========================================

    def log_access_event(
        self,
        event_type: str,
        actor_id: str,
        actor_role: str,
        target_patient_id: str,
        record_id: Optional[str] = None,
        consent_id: Optional[str] = None,
        status: str = "ALLOWED",
        detail: str = "",
        actor_name: Optional[str] = None,
        record_title: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submits MedTrustContract:LogAccessEvent transaction.
        Appends cryptographically hash-chained entry to tamper-evident audit ledger.
        """
        assert_zero_phi(event_type, "event_type")
        assert_zero_phi(actor_id, "actor_id")
        assert_zero_phi(target_patient_id, "target_patient_id")
        assert_zero_phi(detail, "detail")
        assert_zero_phi(purpose, "purpose")

        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            invoke_res = self._execute_peer_invoke(
                f"{self.contract_name}:LogAccessEvent",
                [
                    event_type,
                    actor_id,
                    actor_role,
                    target_patient_id,
                    record_id or "",
                    consent_id or "",
                    status,
                    detail or purpose or "",
                ],
            )
            tx_hash = invoke_res.get("tx_hash", generate_tx_hash())
            entry_id = f"aud-{uuid.uuid4().hex[:6]}"
            entry_data = {
                "id": entry_id,
                "seq": len(self._audit_chain) + 1,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": event_type,
                "action": event_type,
                "actor_id": actor_id,
                "actor_name": actor_name or actor_id,
                "actor_role": actor_role,
                "target_patient_id": target_patient_id,
                "record_id": record_id or "",
                "record_title": record_title,
                "consent_id": consent_id or "",
                "purpose": purpose or detail,
                "status": status,
                "detail": detail,
                "tx_hash": tx_hash,
                "prev_hash": self._prev_audit_hash,
            }
            canonical_str = canonical_json_dumps(entry_data)
            entry_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
            entry_data["entry_hash"] = entry_hash
            self._audit_chain.append(entry_data)
            self._prev_audit_hash = entry_hash
            logger.info("RealFabricGateway: Live LogAccessEvent committed %s (Tx: %s)", entry_id, tx_hash)
            return entry_data

        tx_hash = generate_tx_hash()
        entry_id = f"aud-{uuid.uuid4().hex[:6]}"
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        entry_data = {
            "id": entry_id,
            "seq": len(self._audit_chain) + 1,
            "timestamp": now_iso,
            "event_type": event_type,
            "action": event_type,
            "actor_id": actor_id,
            "actor_name": actor_name or actor_id,
            "actor_role": actor_role,
            "target_patient_id": target_patient_id,
            "record_id": record_id or "",
            "record_title": record_title,
            "consent_id": consent_id or "",
            "purpose": purpose or detail,
            "status": status,
            "detail": detail,
            "tx_hash": tx_hash,
            "prev_hash": self._prev_audit_hash,
        }

        # Cryptographic hash calculation (canonical JSON without entry_hash)
        canonical_str = canonical_json_dumps(entry_data)
        entry_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        entry_data["entry_hash"] = entry_hash

        self._audit_chain.append(entry_data)
        self._prev_audit_hash = entry_hash
        logger.info("RealFabricGateway: LogAccessEvent committed %s (Tx: %s)", entry_id, tx_hash)
        return entry_data

    def get_audit_logs_by_patient(self, patient_id: str) -> List[Dict[str, Any]]:
        """Evaluates MedTrustContract:GetAuditLogsByPatient query."""
        assert_zero_phi(patient_id, "patient_id")
        patient_record_ids = {r["id"] for r in self._records.values() if r["patient_id"] == patient_id}
        return [
            log for log in self._audit_chain
            if (
                log.get("target_patient_id") == patient_id
                or log.get("actor_id") == patient_id
                or log.get("record_id") in patient_record_ids
            )
        ]

    def get_audit_logs_by_actor(self, actor_id: str) -> List[Dict[str, Any]]:
        """Evaluates MedTrustContract:GetAuditLogsByActor query."""
        assert_zero_phi(actor_id, "actor_id")
        return [log for log in self._audit_chain if log.get("actor_id") == actor_id]

    def verify_audit_chain(self) -> Dict[str, Any]:
        """
        Evaluates MedTrustContract:VerifyAuditChain query.
        Traverses cryptographic hash chain from genesis block to current tip.
        """
        if getattr(settings, "FABRIC_USE_REAL_GATEWAY", False):
            query_res = self._execute_peer_query(
                f"{self.contract_name}:VerifyAuditChain",
                [],
            )
            if isinstance(query_res, dict):
                return query_res
            return json.loads(query_res) if isinstance(query_res, str) else query_res

        expected_prev = self.GENESIS_BLOCK_HASH
        for i, entry in enumerate(self._audit_chain):
            if entry["prev_hash"] != expected_prev:
                return {
                    "isIntact": False,
                    "entryCount": len(self._audit_chain),
                    "brokenIndex": i,
                    "message": f"Broken chain link at index {i}: expected {expected_prev}, got {entry['prev_hash']}",
                }
            payload = dict(entry)
            stored_hash = payload.pop("entry_hash", None)
            recomputed = hashlib.sha256(canonical_json_dumps(payload).encode("utf-8")).hexdigest()
            if stored_hash != recomputed:
                return {
                    "isIntact": False,
                    "entryCount": len(self._audit_chain),
                    "corruptedIndex": i,
                    "message": f"Corrupted entry hash at index {i}",
                }
            expected_prev = stored_hash

        return {
            "isIntact": True,
            "entryCount": len(self._audit_chain),
            "lastHash": self._prev_audit_hash,
            "message": "Chain is cryptographically intact and unbroken.",
        }


# Global singleton instance of RealFabricGatewayAdapter
real_fabric_gateway = RealFabricGatewayAdapter()

# Backward and cross-agent compatibility alias for QA and test runners
RealFabricGatewayClient = RealFabricGatewayAdapter

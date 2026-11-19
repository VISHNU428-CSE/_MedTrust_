"""
Real IPFS (Kubo) Client Adapter.
Connects directly to the Kubo RPC API (default: http://127.0.0.1:5001/api/v0).
Enforces SHA-256 integrity verification against ledger checksums upon retrieval.
Strictly avoids silent mock fallbacks in operational runtime.
"""

import hashlib
import logging
import os
import re
import uuid
from typing import Tuple, Optional, Dict, Any
import httpx

from app.config import settings
from app.core.exceptions import ChecksumMismatchError, IPFSConnectionError

logger = logging.getLogger(__name__)

# Safe CID regex: alphanumeric, underscore, hyphen; 10-128 chars. Prevents path traversal.
CID_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{10,128}$")


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 hex digest of raw binary data."""
    return hashlib.sha256(data).hexdigest()


class IPFSClient:
    """
    Client for IPFS Kubo RPC API.
    Handles raw encrypted medical document pinning and content retrieval.
    Supports optional persistent offline caching via MEDTRUST_OFFLINE_STORAGE_DIR.
    """
    def __init__(self, base_url: Optional[str] = None, timeout: Optional[float] = None):
        self.base_url = (base_url or settings.IPFS_RPC_URL).rstrip("/")
        self.timeout = timeout or settings.IPFS_TIMEOUT_SECONDS
        self._offline_cache: Dict[str, bytes] = {}
        self._offline_dir: Optional[str] = None

        offline_env = os.environ.get("MEDTRUST_OFFLINE_STORAGE_DIR")
        if offline_env and offline_env.strip():
            try:
                resolved_dir = os.path.abspath(offline_env.strip())
                os.makedirs(resolved_dir, exist_ok=True)
                self._offline_dir = resolved_dir
                logger.info("IPFSClient: Persistent offline cache directory active: %s", self._offline_dir)
            except Exception as err:
                logger.warning("IPFSClient: Failed to initialize MEDTRUST_OFFLINE_STORAGE_DIR: %s", str(err))

    def _get_safe_cache_path(self, cid: str) -> Optional[str]:
        """Resolves canonical safe filesystem path for a CID within _offline_dir."""
        if not self._offline_dir or not CID_SAFE_PATTERN.match(cid):
            return None
        try:
            target = os.path.abspath(os.path.join(self._offline_dir, f"{cid}.bin"))
            real_dir = os.path.realpath(self._offline_dir)
            real_target = os.path.realpath(target)
            if not real_target.startswith(real_dir + os.sep) and real_target != real_dir:
                return None
            return target
        except Exception:
            return None

    def store_offline_bytes(self, cid: str, data: bytes) -> None:
        """Stores raw ciphertext in offline cache (memory and optional persistent directory)."""
        self._offline_cache[cid] = data
        target_path = self._get_safe_cache_path(cid)
        if target_path:
            tmp_path = f"{target_path}.tmp.{uuid.uuid4().hex}"
            try:
                with open(tmp_path, "wb") as f:
                    f.write(data)
                os.replace(tmp_path, target_path)
            except Exception as write_err:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                logger.warning("IPFSClient: Failed to persist offline ciphertext for CID %s: %s", cid, str(write_err))

    def remove_offline_bytes(self, cid: str) -> bool:
        """
        Removes raw ciphertext from offline cache (memory and optional persistent directory).
        Returns True if the content was removed from either memory or disk.
        """
        removed = False
        if cid in self._offline_cache:
            del self._offline_cache[cid]
            removed = True
        target_path = self._get_safe_cache_path(cid)
        if target_path and os.path.isfile(target_path):
            try:
                os.remove(target_path)
                removed = True
                logger.info("IPFSClient: Removed persistent offline ciphertext for CID %s", cid)
            except Exception as e:
                logger.warning("IPFSClient: Failed to remove offline cache file for CID %s: %s", cid, str(e))
        return removed

    def _read_offline_bytes(self, cid: str, expected_sha256: Optional[str] = None) -> Optional[bytes]:
        """Retrieves ciphertext from memory or persistent disk cache, verifying integrity."""
        raw_bytes = self._offline_cache.get(cid)

        if raw_bytes is None:
            target_path = self._get_safe_cache_path(cid)
            if target_path and os.path.isfile(target_path):
                try:
                    with open(target_path, "rb") as f:
                        raw_bytes = f.read()
                except Exception as read_err:
                    logger.warning("IPFSClient: Error reading persistent cache for CID %s: %s", cid, str(read_err))
                    raw_bytes = None

        if raw_bytes is None:
            return None

        if expected_sha256:
            actual_sha256 = compute_sha256(raw_bytes)
            if actual_sha256.lower() != expected_sha256.lower():
                raise ChecksumMismatchError(
                    f"CRITICAL SECURITY ALERT: Checksum mismatch for CID {cid}! "
                    f"Expected {expected_sha256}, calculated {actual_sha256}. "
                    "Data has been tampered with or corrupted in transit!"
                )

        self._offline_cache[cid] = raw_bytes
        return raw_bytes

    @property
    def _client_timeout(self) -> httpx.Timeout:
        """Returns httpx.Timeout with a fast connect timeout (0.8s) to avoid OS socket stalls when offline."""
        return httpx.Timeout(self.timeout, connect=min(0.8, self.timeout))

    def check_connection(self) -> Dict[str, Any]:
        """
        Queries Kubo /api/v0/id to inspect daemon connectivity.
        Raises IPFSConnectionError if offline.
        """
        try:
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/id")
                if res.status_code == 200:
                    data = res.json()
                    return {
                        "status": "connected",
                        "id": data.get("ID"),
                        "agentVersion": data.get("AgentVersion"),
                        "protocolVersion": data.get("ProtocolVersion"),
                    }
                raise IPFSConnectionError(f"IPFS daemon responded with HTTP {res.status_code}: {res.text}")
        except httpx.RequestError as e:
            raise IPFSConnectionError(f"Cannot connect to IPFS Kubo RPC at {self.base_url}: {str(e)}") from e

    def add_bytes(self, content: bytes, pin: bool = True) -> Tuple[str, str]:
        """
        Pins raw bytes to IPFS Kubo node via /api/v0/add.
        Computes SHA-256 checksum before transport.
        Returns:
            (cid, sha256_checksum)
        """
        sha256_checksum = compute_sha256(content)
        try:
            files = {"file": ("encrypted_record.bin", content, "application/octet-stream")}
            params = {"pin": "true" if pin else "false", "cid-version": "1"}
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/add", params=params, files=files)
                if res.status_code == 200:
                    data = res.json()
                    cid = data.get("Hash")
                    if not cid:
                        raise IPFSConnectionError(f"Unexpected Kubo response: missing Hash in {data}")
                    logger.info("Pinned content to IPFS with CID: %s (SHA-256: %s)", cid, sha256_checksum)
                    self.store_offline_bytes(cid, content)
                    return cid, sha256_checksum
                raise IPFSConnectionError(f"IPFS upload failed with status {res.status_code}: {res.text}")
        except httpx.RequestError as e:
            raise IPFSConnectionError(f"IPFS Kubo connection failed during upload to {self.base_url}: {str(e)}") from e

    def get_bytes(self, cid: str, expected_sha256: Optional[str] = None) -> bytes:
        """
        Retrieves raw payload by CID via /api/v0/cat.
        Rigorously verifies computed SHA-256 digest against expected_sha256.
        Raises ChecksumMismatchError if content has been corrupted or tampered.
        Raises KeyError if the CID block is not found on the local IPFS node.
        Raises IPFSConnectionError on connection timeouts or daemon communication failures.
        """
        try:
            params = {"arg": cid, "offline": "true"}
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/cat", params=params)
                if res.status_code == 200:
                    raw_bytes = res.content
                    if expected_sha256:
                        actual_sha256 = compute_sha256(raw_bytes)
                        if actual_sha256.lower() != expected_sha256.lower():
                            raise ChecksumMismatchError(
                                f"CRITICAL SECURITY ALERT: Checksum mismatch for CID {cid}! "
                                f"Expected {expected_sha256}, calculated {actual_sha256}. "
                                "Data has been tampered with or corrupted in transit!"
                            )
                    self.store_offline_bytes(cid, raw_bytes)
                    return raw_bytes

                # Distinguish CID not found from daemon error
                is_missing = res.status_code == 404 or (
                    res.status_code in (400, 500)
                    and any(
                        term in res.text.lower()
                        for term in (
                            "not found",
                            "no such",
                            "could not find",
                            "does not exist",
                            "merkledag",
                            "key not found",
                            "block not found",
                        )
                    )
                )
                if is_missing:
                    cached = self._read_offline_bytes(cid, expected_sha256)
                    if cached is not None:
                        return cached
                    raise KeyError(f"IPFS CID block not found in local node storage: {cid}")

                raise IPFSConnectionError(f"IPFS retrieve failed with status {res.status_code}: {res.text}")
        except httpx.TimeoutException as e:
            cached = self._read_offline_bytes(cid, expected_sha256)
            if cached is not None:
                return cached
            raise IPFSConnectionError(
                f"IPFS Kubo connection timed out during retrieval from {self.base_url}: {str(e)}"
            ) from e
        except httpx.RequestError as e:
            cached = self._read_offline_bytes(cid, expected_sha256)
            if cached is not None:
                return cached
            raise IPFSConnectionError(
                f"IPFS Kubo connection failed during retrieval from {self.base_url}: {str(e)}"
            ) from e

    def pin_ls(self, cid: Optional[str] = None) -> Dict[str, Any]:
        """
        Queries Kubo /api/v0/pin/ls to inspect pin state.
        Returns dict containing pinned keys, or empty dict if the CID is not pinned.
        Raises ValueError if provided cid does not match CID_SAFE_PATTERN.
        Raises IPFSConnectionError on connection failure or unexpected daemon error.
        """
        params: Dict[str, str] = {"type": "all"}
        if cid is not None:
            if not CID_SAFE_PATTERN.match(cid):
                raise ValueError(f"Invalid CID format for pin inspection: {cid}")
            params["arg"] = cid

        try:
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/pin/ls", params=params)
                if res.status_code == 200:
                    return res.json().get("Keys", {})
                if "not pinned" in res.text.lower():
                    return {}
                raise IPFSConnectionError(f"IPFS pin ls failed with status {res.status_code}: {res.text}")
        except httpx.RequestError as e:
            raise IPFSConnectionError(f"IPFS Kubo connection failed during pin ls at {self.base_url}: {str(e)}") from e

    def pin_add(self, cid: str) -> bool:
        """
        Pins an existing CID on the Kubo daemon via /api/v0/pin/add.
        Raises ValueError if cid does not match CID_SAFE_PATTERN.
        Raises IPFSConnectionError on connection failure or daemon error.
        """
        if not CID_SAFE_PATTERN.match(cid):
            raise ValueError(f"Invalid CID format for pinning: {cid}")
        try:
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/pin/add", params={"arg": cid})
                if res.status_code == 200:
                    logger.info("Successfully pinned CID to IPFS: %s", cid)
                    return True
                raise IPFSConnectionError(f"IPFS pin add failed with status {res.status_code}: {res.text}")
        except httpx.RequestError as e:
            raise IPFSConnectionError(f"IPFS Kubo connection failed during pin add at {self.base_url}: {str(e)}") from e

    def pin_rm(self, cid: str) -> bool:
        """
        Unpins a CID on the Kubo daemon via /api/v0/pin/rm.
        Raises ValueError if cid does not match CID_SAFE_PATTERN.
        Raises IPFSConnectionError on connection failure or daemon error.
        """
        if not CID_SAFE_PATTERN.match(cid):
            raise ValueError(f"Invalid CID format for unpinning: {cid}")
        try:
            with httpx.Client(timeout=self._client_timeout) as client:
                res = client.post(f"{self.base_url}/pin/rm", params={"arg": cid})
                if res.status_code == 200:
                    logger.info("Successfully unpinned CID from IPFS: %s", cid)
                    return True
                if "not pinned" in res.text.lower():
                    logger.info("CID %s was already not pinned", cid)
                    return False
                raise IPFSConnectionError(f"IPFS pin rm failed with status {res.status_code}: {res.text}")
        except httpx.RequestError as e:
            raise IPFSConnectionError(f"IPFS Kubo connection failed during pin rm at {self.base_url}: {str(e)}") from e


# Global singleton instance configured from settings
ipfs_client = IPFSClient()

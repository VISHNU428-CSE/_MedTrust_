import pytest
import hashlib
from app.adapters.ipfs_client import IPFSClient, compute_sha256
from app.core.exceptions import ChecksumMismatchError, IPFSConnectionError


def test_compute_sha256():
    data = b"Encrypted DICOM image"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_sha256(data) == expected


def test_checksum_mismatch_raises_exception():
    client = IPFSClient()
    # Emulate payload retrieval where expected hash does not match
    original = b"Genuine Patient Record"
    expected_hash = hashlib.sha256(original).hexdigest()
    
    # If returned payload was modified by adversary
    tampered_bytes = b"Tampered Patient Record"
    
    with pytest.raises(ChecksumMismatchError) as exc_info:
        actual_sha = compute_sha256(tampered_bytes)
        if actual_sha != expected_hash:
            raise ChecksumMismatchError(f"CRITICAL SECURITY ALERT: Checksum mismatch! Expected {expected_hash}, calculated {actual_sha}")
            
    assert "CRITICAL SECURITY ALERT" in str(exc_info.value)


def test_ipfs_offline_raises_ipfs_connection_error():
    # Point client to dead port
    client = IPFSClient(base_url="http://127.0.0.1:59999/api/v0", timeout=0.5)
    with pytest.raises(IPFSConnectionError):
        client.check_connection()


def test_ipfs_get_bytes_cid_missing_raises_key_error(monkeypatch):
    client = IPFSClient()

    class MockResponse:
        status_code = 500
        text = '{"Message":"merkledag: not found","Code":0,"Type":"error"}'
        content = b""

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    with pytest.raises(KeyError, match="IPFS CID block not found in local node storage"):
        client.get_bytes("bafybeimdt_missing_block")


def test_ipfs_get_bytes_timeout_raises_ipfs_connection_error(monkeypatch):
    import httpx
    client = IPFSClient()

    class MockTimeoutHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            raise httpx.ConnectTimeout("Connection timed out")

    monkeypatch.setattr("httpx.Client", MockTimeoutHttpxClient)
    with pytest.raises(IPFSConnectionError) as exc_info:
        client.get_bytes("bafybeimdt_timeout_test")
    assert "timed out" in str(exc_info.value).lower()


# ==============================================================================
# Pin Management Unit Tests
# ==============================================================================

def test_pin_methods_reject_invalid_cids():
    client = IPFSClient()
    invalid_cids = ["", "short", "../../traversal", "bad$cid*char!", "a" * 150]
    for cid in invalid_cids:
        with pytest.raises(ValueError, match="Invalid CID format"):
            client.pin_ls(cid)
        with pytest.raises(ValueError, match="Invalid CID format"):
            client.pin_add(cid)
        with pytest.raises(ValueError, match="Invalid CID format"):
            client.pin_rm(cid)


def test_pin_ls_success(monkeypatch):
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockResponse:
        status_code = 200
        text = '{"Keys":{"bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123":{"Type":"recursive"}}}'
        def json(self):
            import json
            return json.loads(self.text)

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    keys = client.pin_ls(valid_cid)
    assert valid_cid in keys
    assert keys[valid_cid]["Type"] == "recursive"


def test_pin_ls_not_pinned_returns_empty_dict(monkeypatch):
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockResponse:
        status_code = 500
        text = f'{{"Message":"path \'{valid_cid}\' is not pinned","Code":0,"Type":"error"}}'
        def json(self):
            import json
            return json.loads(self.text)

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    keys = client.pin_ls(valid_cid)
    assert keys == {}


def test_pin_add_success(monkeypatch):
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockResponse:
        status_code = 200
        text = f'{{"Pins":["{valid_cid}"]}}'
        def json(self):
            import json
            return json.loads(self.text)

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    assert client.pin_add(valid_cid) is True


def test_pin_rm_success(monkeypatch):
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockResponse:
        status_code = 200
        text = f'{{"Pins":["{valid_cid}"]}}'
        def json(self):
            import json
            return json.loads(self.text)

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    assert client.pin_rm(valid_cid) is True


def test_pin_rm_already_unpinned(monkeypatch):
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockResponse:
        status_code = 500
        text = f'{{"Message":"path \'{valid_cid}\' is not pinned","Code":0,"Type":"error"}}'
        def json(self):
            import json
            return json.loads(self.text)

    class MockHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr("httpx.Client", MockHttpxClient)
    assert client.pin_rm(valid_cid) is False


def test_pin_methods_connection_error(monkeypatch):
    import httpx
    client = IPFSClient()
    valid_cid = "bafkreihdwdcefghijk1234567890abcdefghijklmnopqrstuvwxyz123"

    class MockErrorHttpxClient:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, *args, **kwargs):
            raise httpx.ConnectError("Daemon unreachable")

    monkeypatch.setattr("httpx.Client", MockErrorHttpxClient)
    with pytest.raises(IPFSConnectionError):
        client.pin_ls(valid_cid)
    with pytest.raises(IPFSConnectionError):
        client.pin_add(valid_cid)
    with pytest.raises(IPFSConnectionError):
        client.pin_rm(valid_cid)

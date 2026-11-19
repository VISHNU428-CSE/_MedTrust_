"""
Domain exception hierarchy for MedTrust Backend.
Aligns with QA verification invariants.
"""


class MedTrustException(Exception):
    """Base exception for all MedTrust domain errors."""
    def __init__(self, message: str, code: int = 500, reason: str = "INTERNAL_ERROR"):
        super().__init__(message)
        self.message = message
        self.code = code
        self.reason = reason


class ChecksumMismatchError(MedTrustException):
    """Raised when IPFS retrieved content digest does not match the ledger registered checksum."""
    def __init__(self, message: str):
        super().__init__(message, code=422, reason="CHECKSUM_MISMATCH")


class AccessDeniedError(MedTrustException):
    """Raised when RBAC or Consent authorization check fails."""
    def __init__(self, message: str, code: int = 403, reason: str = "FORBIDDEN"):
        super().__init__(message, code=code, reason=reason)


class IPFSConnectionError(MedTrustException):
    """Raised when IPFS Kubo daemon is unreachable or fails to respond."""
    def __init__(self, message: str):
        super().__init__(message, code=503, reason="IPFS_UNAVAILABLE")


class FabricGatewayError(MedTrustException):
    """Raised when Hyperledger Fabric Gateway interaction fails."""
    def __init__(self, message: str, code: int = 502, reason: str = "FABRIC_GATEWAY_ERROR"):
        super().__init__(message, code=code, reason=reason)


class RecordNotFoundError(MedTrustException):
    """Raised when a requested medical record does not exist."""
    def __init__(self, message: str):
        super().__init__(message, code=404, reason="RECORD_NOT_FOUND")


class ConsentNotFoundError(MedTrustException):
    """Raised when a specified consent record does not exist."""
    def __init__(self, message: str):
        super().__init__(message, code=404, reason="CONSENT_NOT_FOUND")


class EncryptionError(MedTrustException):
    """Raised when AES-256-GCM encryption or decryption fails."""
    def __init__(self, message: str):
        super().__init__(message, code=400, reason="ENCRYPTION_ERROR")


class PHIViolationError(ValueError, MedTrustException):
    """Raised when unencrypted Protected Health Information (PHI) or secrets are detected in ledger payloads."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
        self.code = 400
        self.reason = "PHI_VIOLATION_DETECTED"

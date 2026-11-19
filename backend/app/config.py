"""
Configuration settings for MedTrust FastAPI Backend.
Uses Pydantic Settings for environment management.
"""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MedTrust Decentralized Healthcare API"
    VERSION: str = "v1.0.0"
    API_V1_STR: str = "/api/v1"
    PORT: int = 8001

    # Database Persistence (SQLite via SQLAlchemy)
    DATABASE_URL: str = "sqlite:///./medtrust.db"

    # JWT Authentication
    JWT_SECRET_KEY: str = "medtrust-test-secret-key-do-not-use-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # IPFS (Kubo) RPC & Gateway Configuration
    IPFS_RPC_URL: str = "http://127.0.0.1:5001/api/v0"
    IPFS_GATEWAY_URL: str = "http://127.0.0.1:8080/ipfs"
    IPFS_TIMEOUT_SECONDS: float = 10.0

    # Hyperledger Fabric Gateway Configuration
    FABRIC_CHANNEL: str = "medtrust-channel"
    FABRIC_CHAINCODE: str = "medtrust-contract"
    FABRIC_CONTRACT_NAME: str = "MedTrustContract"
    FABRIC_MSP_ID: str = "Org1MSP"
    FABRIC_PEER_ENDPOINT: str = "localhost:7051"
    FABRIC_TIMEOUT_SECONDS: float = 10.0
    FABRIC_CONNECTION_PROFILE_PATH: str = "blockchain/network/connection-org1.json"
    FABRIC_CRYPTO_PATH: str = "blockchain/network/crypto-config"
    FABRIC_USER_CERT_PATH: str = "blockchain/network/crypto-config/peerOrganizations/org1.medtrust.com/users/User1@org1.medtrust.com/msp/signcerts/User1@org1.medtrust.com-cert.pem"
    FABRIC_USER_KEY_DIR: str = "blockchain/network/crypto-config/peerOrganizations/org1.medtrust.com/users/User1@org1.medtrust.com/msp/keystore"
    FABRIC_TLS_CERT_PATH: str = "blockchain/network/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt"
    FABRIC_USE_REAL_GATEWAY: bool = False

    # Encryption Configuration (AES-256-GCM)
    DEFAULT_MASTER_KEY_HEX: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    MEDTRUST_MASTER_KEK: Optional[str] = None  # 32-byte base64-encoded Master KEK
    ENVELOPE_ENCRYPTION_ENABLED: bool = True

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "*"
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()

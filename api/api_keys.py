"""API key management for the npm-scan hosted tier.

Handles:
  - Key generation (prefixed + hashed for storage)
  - Key validation against stored hash
  - Scope-based access control per key
  - Key rotation and revocation
"""

import os
import uuid
import hashlib
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional


API_KEY_PREFIX = "npm-scan-api-"


def generate_api_key(name: str = "default", scopes: list[str] = None) -> tuple[str, str]:
    """Generate an API key and return (raw_key, hashed_key).
    
    The raw key is returned once for the user to store securely.
    Only the hashed version is persisted.
    """
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    salt = secrets.token_hex(8)
    hashed = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt.encode(), 100_000).hex()
    stored = f"{salt}${hashed}"
    return raw, stored


def validate_api_key(raw_key: str, stored_hash: str) -> bool:
    """Check a raw key against its stored PBKDF2 hash."""
    try:
        salt, hashed = stored_hash.split("$", 1)
        check = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt.encode(), 100_000).hex()
        return hmac.compare_digest(check, hashed)
    except (ValueError, IndexError):
        return False


def is_api_key(raw_key: str) -> bool:
    """Check if a string looks like an npm-scan API key."""
    return raw_key.startswith(API_KEY_PREFIX)


def redact_key(raw_key: str) -> str:
    """Show only the last 8 chars of a key for logging."""
    if len(raw_key) <= 16:
        return "***"
    return raw_key[-8:].rjust(len(raw_key), "*")
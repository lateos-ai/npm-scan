"""Shared auth dependencies for the npm-scan API.

Handles:
  - JWT access + refresh tokens
  - API key validation
  - Session management
  - RBAC enforcement
  - License feature gating
"""

import os
import uuid
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Header, HTTPException, status, Depends, Request
from pydantic import BaseModel
from jose import jwt, JWTError

JWT_SECRET = os.environ.get("JWT_SECRET", os.urandom(32).hex())
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("JWT_REFRESH_DAYS", "30"))


class UserSession(BaseModel):
    user_id: str
    email: str
    name: str
    team_id: Optional[str] = None
    role: str = "viewer"
    auth_method: str = "password"  # password, saml, api_key
    idp: Optional[str] = None


class TokenPayload(BaseModel):
    sub: str  # user_id
    email: str
    role: str
    team_id: Optional[str] = None
    exp: datetime
    iat: datetime
    jti: str


def create_access_token(session: UserSession) -> str:
    """Create a JWT access token from a user session."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": session.user_id,
        "email": session.email,
        "role": session.role,
        "team_id": session.team_id,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(session: UserSession) -> str:
    """Create a long-lived refresh token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": session.user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> TokenPayload:
    """Verify and decode a JWT token. Raises 401 on failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenPayload(**payload)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    authorization: Optional[str] = Header(None),
) -> UserSession:
    """Dependency: extracts authenticated user from Bearer token or API key."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Use: Bearer <token>",
        )

    # Try JWT first
    try:
        payload = verify_token(token)
        return UserSession(
            user_id=payload.sub,
            email=payload.email,
            name="",
            role=payload.role,
            team_id=payload.team_id,
            auth_method="token",
        )
    except HTTPException:
        pass

    # Try API key (lookup in-memory or PostgreSQL in production)
    # For now, validate format and return limited session
    if token.startswith("npm-scan-api-"):
        return UserSession(
            user_id="api-user",
            email="api@npm-scan.io",
            name="API User",
            role="viewer",
            auth_method="api_key",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
    )


def require_role(required_roles: list[str]):
    """Dependency factory: requires one of the specified roles."""
    async def _check(current_user: UserSession = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of these roles: {required_roles}",
            )
        return current_user
    return _check


def require_feature(feature: str):
    """Dependency factory: requires a specific license feature flag."""
    async def _check():
        license_key = os.environ.get("NPM_SCAN_LICENSE_KEY", "")
        if not license_key:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"Feature '{feature}' requires a premium/enterprise license key",
            )
        # Delegate to Node.js license module via subprocess or bundled validation
        # For now, check if it's an enterprise key format
        if not license_key.startswith("npm-scan-"):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Invalid license key format",
            )
        return True
    return _check
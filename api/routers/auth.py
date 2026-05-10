"""Authentication endpoints — login, register, API key management, SAML status."""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
import os

from ..deps import get_current_user, UserSession
from ..saml import get_saml_config

router = APIRouter()


class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str
    team_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthMethodsResponse(BaseModel):
    password: bool
    saml: bool
    saml_entity_id: Optional[str] = None
    saml_login_url: Optional[str] = None


@router.get("/methods")
async def auth_methods():
    """List available authentication methods for this instance."""
    saml_cfg = get_saml_config()
    saml_configured = saml_cfg.is_configured()
    return AuthMethodsResponse(
        password=True,
        saml=saml_configured,
        saml_entity_id=saml_cfg.entity_id if saml_configured else None,
        saml_login_url="/api/v1/sso/login" if saml_configured else None,
    )


@router.get("/me")
async def get_me(current_user: UserSession = Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "name": current_user.name,
        "role": current_user.role,
        "auth_method": current_user.auth_method,
    }


@router.post("/register", response_model=TokenResponse)
async def register(req: RegisterRequest):
    raise HTTPException(status_code=501, detail="Registration requires PostgreSQL backend — not yet connected")


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    raise HTTPException(status_code=501, detail="Login requires PostgreSQL backend — not yet connected")


@router.get("/saml")
async def saml_redirect():
    """Convenience redirect to SAML login."""
    saml_cfg = get_saml_config()
    if not saml_cfg.is_configured():
        raise HTTPException(status_code=501, detail="SAML not configured")
    return RedirectResponse(url="/api/v1/sso/login")
"""Authentication endpoints — login, register, API key management."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional
import os

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


@router.post("/register", response_model=TokenResponse)
async def register(req: RegisterRequest):
    raise HTTPException(status_code=501, detail="Registration requires PostgreSQL backend — not yet connected")


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    raise HTTPException(status_code=501, detail="Login requires PostgreSQL backend — not yet connected")
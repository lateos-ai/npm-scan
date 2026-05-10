"""Webhook endpoints — register, list, delete webhooks."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
from datetime import datetime
import hashlib
import hmac
import json
import os

router = APIRouter()


class WebhookCreate(BaseModel):
    url: HttpUrl
    events: List[str] = ["scan.completed", "finding.critical"]


class Webhook(BaseModel):
    id: str
    url: str
    events: List[str]
    active: bool = True
    secret: Optional[str] = None
    created_at: datetime


HOOKS_DB: list[Webhook] = []


@router.post("/webhooks", status_code=201)
async def create_webhook(hook: WebhookCreate):
    """Register a new webhook endpoint."""
    wh = Webhook(
        id=hash(str(hook.url) + str(datetime.now())),
        url=str(hook.url),
        events=list(set(hook.events)),
        secret=os.urandom(16).hex(),
        created_at=datetime.now(),
    )
    HOOKS_DB.append(wh)
    return wh


@router.get("/webhooks")
async def list_webhooks():
    """List all registered webhooks."""
    return HOOKS_DB


@router.delete("/webhooks/{hook_id}")
async def delete_webhook(hook_id: str):
    """Delete a webhook by ID."""
    for i, wh in enumerate(HOOKS_DB):
        if wh.id == hook_id:
            HOOKS_DB.pop(i)
            return {"deleted": hook_id}
    raise HTTPException(status_code=404, detail="Webhook not found")


async def dispatch_webhooks(event: str, payload: dict):
    """Dispatch an event to all subscribed webhooks (called by worker)."""
    import httpx

    for wh in HOOKS_DB:
        if not wh.active or event not in wh.events:
            continue
        body = json.dumps({"event": event, "payload": payload, "timestamp": datetime.now().isoformat()})
        sig = hmac.new(wh.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        async with httpx.AsyncClient() as client:
            try:
                await client.post(wh.url, content=body, headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": sig,
                })
            except Exception:
                pass  # log failure in production
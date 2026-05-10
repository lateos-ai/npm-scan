"""Scan endpoints — submit, list, retrieve scans and findings."""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

router = APIRouter()


class ScanRequest(BaseModel):
    package_name: str
    version: Optional[str] = "latest"


class Finding(BaseModel):
    atk_id: str
    severity: str
    title: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None


class Scan(BaseModel):
    id: str
    package_name: str
    version: str
    status: str
    scanned_at: datetime
    findings: List[Finding] = []


SCANS_DB: list[Scan] = []


@router.post("/scan", status_code=201)
async def submit_scan(req: ScanRequest):
    """Submit a package for scanning (delegates to Node.js CLI)."""
    raise HTTPException(
        status_code=501,
        detail="Scan execution requires async worker — use `npm-scan scan <package>` via CLI"
    )


@router.get("/scans", response_model=List[Scan])
async def list_scans(limit: int = Query(10, ge=1, le=100)):
    """List recent scans."""
    return SCANS_DB[-limit:][::-1]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan details by ID."""
    for scan in SCANS_DB:
        if scan.id == scan_id:
            return scan
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@router.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: str):
    """Get findings for a specific scan."""
    for scan in SCANS_DB:
        if scan.id == scan_id:
            return scan.findings
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
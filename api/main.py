"""
npm-scan REST API — FastAPI application.
Requires premium/enterprise license key for all endpoints.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import os

from .routers import scans, webhooks, auth, health

app = FastAPI(
    title="npm-scan API",
    version=os.environ.get("npm_package_version", "0.5.0"),
    description="npm supply chain security scanner — REST API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/v1", tags=["scans"])
app.include_router(webhooks.router, prefix="/api/v1", tags=["webhooks"])


def main():
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.environ.get("API_HOST", "0.0.0.0"),
        port=int(os.environ.get("API_PORT", "8000")),
        reload=os.environ.get("API_RELOAD", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
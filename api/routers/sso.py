"""SSO / SAML 2.0 endpoints for npm-scan enterprise tier.

Endpoints:
  GET  /sso/metadata    — SP metadata XML for IdP registration
  GET  /sso/login       — SP-initiated SSO redirect
  POST /sso/acs         — Assertion Consumer Service (IdP POSTs here)
  POST /sso/slo         — Single Logout
  GET  /sso/session     — Check current SAML session status
  POST /sso/provision   — Auto-provision user from SAML attributes
"""

import os
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel

from ..deps import UserSession, create_access_token, create_refresh_token, get_current_user, require_feature
from ..saml import get_saml_config, SAMLConfig

logger = logging.getLogger("npm-scan.sso")

router = APIRouter(prefix="/sso", tags=["sso"])

# In-memory SAML session store (PostgreSQL in production)
_saml_sessions: dict[str, dict] = {}

# User provisioning store (PostgreSQL in production)
_provisioned_users: dict[str, UserSession] = {}


def _build_auth_request(config: SAMLConfig) -> tuple[str, str]:
    """Build SAML AuthnRequest and return (redirect_url, request_id)."""
    import base64
    from xml.etree import ElementTree as ET

    request_id = "_" + uuid.uuid4().hex
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    authn = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
        attrib={
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": now,
            "Destination": config.idp_sso_url,
            "AssertionConsumerServiceURL": config.acs_url,
            "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "ForceAuthn": "false",
            "IsPassive": "false",
        },
    )
    issuer = ET.SubElement(
        authn,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
    )
    issuer.text = config.entity_id

    nameid = ET.SubElement(
        authn,
        "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
        attrib={
            "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "AllowCreate": "true",
        },
    )

    raw = ET.tostring(authn, encoding="unicode")
    encoded = base64.b64encode(raw.encode()).decode()

    params = urlencode({"SAMLRequest": encoded})
    redirect_url = f"{config.idp_sso_url}?{params}"
    return redirect_url, request_id


def _parse_saml_response(saml_response: str, config: SAMLConfig) -> dict:
    """Parse and validate a SAML Response.
    
    In production this uses python3-saml for full XML sig validation.
    For the skeleton, we extract attributes from the base64-decoded XML.
    """
    import base64
    from xml.etree import ElementTree as ET

    try:
        decoded = base64.b64decode(saml_response)
        root = ET.fromstring(decoded)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid SAML response: {e}")

    ns = {
        "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    }

    # Extract attributes from the SAML assertion
    attrs = {}
    for attr_stmt in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"):
        for attr in attr_stmt.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
            name = attr.get("Name", "")
            values = [v.text or "" for v in attr.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")]
            attrs[name] = values[0] if len(values) == 1 else values

    # Extract NameID
    name_id = None
    for subject in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Subject"):
        for nid in subject.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
            name_id = nid.text
            break

    return {
        "name_id": name_id,
        "attributes": attrs,
        "issuer": root.findtext(".//saml2:Issuer", "", ns),
        "session_index": root.findtext(".//saml2:AuthnStatement/@SessionIndex", ""),
    }


def _provision_user(assertion_data: dict, config: SAMLConfig) -> UserSession:
    """Create or update a user from SAML attributes.
    
    In production this upserts into PostgreSQL. For the skeleton,
    we maintain an in-memory store.
    """
    mapping = config.attribute_mapping
    attrs = assertion_data.get("attributes", {})
    raw_name_id = assertion_data.get("name_id", "")

    email = (
        attrs.get(mapping.get("email", "email"))
        or attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
        or raw_name_id
        or ""
    )
    display_name = (
        attrs.get(mapping.get("name", "displayName"))
        or attrs.get("http://schemas.microsoft.com/identity/claims/displayname")
        or email.split("@")[0]
        or "SAML User"
    )
    groups = attrs.get(mapping.get("groups", "groups"), [])
    if isinstance(groups, str):
        groups = [groups]

    # Determine role from groups or admin domains
    role = config.default_role
    if isinstance(groups, list):
        group_str = " ".join(groups).lower()
        if "admin" in group_str:
            role = "admin"
        elif "editor" in group_str:
            role = "editor"
    if config.admin_domains:
        email_domain = email.split("@")[-1] if "@" in email else ""
        if email_domain in config.admin_domains:
            role = "admin"

    user_id = str(uuid.uuid4())
    if raw_name_id:
        _provisioned_users[raw_name_id] = UserSession(
            user_id=user_id,
            email=email,
            name=display_name,
            role=role,
            auth_method="saml",
            idp=assertion_data.get("issuer", "unknown"),
        )

    return _provisioned_users.get(raw_name_id, UserSession(
        user_id=user_id,
        email=email,
        name=display_name,
        role=role,
        auth_method="saml",
    ))


@router.get("/metadata")
async def saml_metadata():
    """Generate SAML 2.0 SP metadata XML for IdP registration."""
    config = get_saml_config()
    if not config.is_configured():
        return HTMLResponse(
            content="<h1>SAML Not Configured</h1><p>Set SAML_IDP_SSO_URL and SAML_IDP_ENTITY_ID environment variables.</p>",
            status_code=200,
        )

    from xml.etree import ElementTree as ET

    root = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor",
        attrib={
            "entityID": config.entity_id,
            "xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        },
    )

    sp_sso = ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor",
        attrib={
            "protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
            "AuthnRequestsSigned": "true",
            "WantAssertionsSigned": str(config.want_assertions_signed).lower(),
        },
    )

    # Key descriptor (if SP cert is configured)
    if config.sp_x509_cert:
        key_desc = ET.SubElement(
            sp_sso,
            "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor",
            attrib={"use": "signing"},
        )
        key_info = ET.SubElement(
            key_desc,
            "{http://www.w3.org/2000/09/xmldsig#}KeyInfo",
        )
        x509_data = ET.SubElement(
            key_info,
            "{http://www.w3.org/2000/09/xmldsig#}X509Data",
        )
        x509_cert = ET.SubElement(
            x509_data,
            "{http://www.w3.org/2000/09/xmldsig#}X509Certificate",
        )
        x509_cert.text = config.sp_x509_cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()

    # ACS
    acs = ET.SubElement(
        sp_sso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService",
        attrib={
            "index": "0",
            "isDefault": "true",
            "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "Location": config.acs_url,
        },
    )

    # SLO
    slo = ET.SubElement(
        sp_sso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService",
        attrib={
            "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "Location": config.slo_url,
        },
    )

    # NameID format
    nid = ET.SubElement(
        sp_sso,
        "{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat",
    )
    nid.text = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    raw = ET.tostring(root, encoding="unicode")
    return Response(content=raw, media_type="application/xml")


@router.get("/login")
async def saml_login():
    """SP-initiated SSO. Redirects user to IdP with SAML AuthnRequest."""
    config = get_saml_config()
    if not config.is_configured():
        raise HTTPException(
            status_code=501,
            detail="SAML not configured. Set SAML_IDP_SSO_URL and SAML_IDP_ENTITY_ID env vars",
        )

    redirect_url, request_id = _build_auth_request(config)
    _saml_sessions[request_id] = {"created_at": datetime.now(timezone.utc).isoformat()}
    return RedirectResponse(url=redirect_url)


@router.post("/acs")
async def saml_acs(request: Request):
    """Assertion Consumer Service — IdP POSTs SAML Response here after authentication.
    
    Returns JWT tokens on success.
    """
    form = await request.form()
    saml_response = form.get("SAMLResponse")
    relay_state = form.get("RelayState", "/")

    if not saml_response:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")

    config = get_saml_config()
    assertion_data = _parse_saml_response(saml_response, config)

    if not assertion_data.get("name_id"):
        raise HTTPException(status_code=400, detail="No NameID in SAML assertion")

    # Provision or look up user
    user = _provision_user(assertion_data, config)
    if not user:
        raise HTTPException(status_code=403, detail="User provisioning failed")

    # Store SAML session
    _saml_sessions[assertion_data["name_id"]] = {
        "user_id": user.user_id,
        "email": user.email,
        "session_index": assertion_data.get("session_index", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Issue JWT
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user.user_id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
        },
    }


@router.post("/slo")
async def saml_slo(request: Request):
    """Single Logout — terminates SAML session and invalidates tokens."""
    form = await request.form()
    logout_request = form.get("SAMLRequest")

    if logout_request:
        # Decode to find the NameID and clear session
        import base64
        from xml.etree import ElementTree as ET
        try:
            decoded = base64.b64decode(logout_request)
            root = ET.fromstring(decoded)
            ns = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
            name_id = root.findtext(".//saml2:NameID", "", ns)
            if name_id and name_id in _saml_sessions:
                del _saml_sessions[name_id]
        except Exception:
            pass

    return {
        "status": "logged_out",
        "message": "SAML session terminated",
    }


@router.get("/session")
async def saml_session(current_user: UserSession = Depends(get_current_user)):
    """Current SAML session status."""
    return {
        "authenticated": True,
        "user": {
            "id": current_user.user_id,
            "email": current_user.email,
            "name": current_user.name,
            "role": current_user.role,
        },
        "auth_method": current_user.auth_method,
        "idp": current_user.idp,
    }


@router.get("/config")
async def saml_config_status():
    """Check whether SAML is configured (no auth required)."""
    config = get_saml_config()
    return {
        "configured": config.is_configured(),
        "entity_id": config.entity_id,
        "acs_url": config.acs_url,
        "auto_provision": config.auto_provision,
        "default_role": config.default_role,
    }
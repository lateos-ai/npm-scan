"""npm-scan SAML 2.0 Service Provider implementation.

Supports:
  - IdP-initiated SSO
  - SP-initiated SSO
  - Signed + encrypted assertions
  - Metadata exchange
  - Single Logout (SLO)
  - Auto-provisioning via attribute mapping

Requires enterprise license with 'sso' feature flag.
"""

import os
import json
from typing import Optional
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SAMLConfig:
    """SAML 2.0 configuration loaded from environment / config file."""
    # SP identity
    entity_id: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_SP_ENTITY_ID",
            "https://npm-scan.io/saml/metadata"
        )
    )
    acs_url: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_ACS_URL",
            "https://npm-scan.io/api/v1/sso/acs"
        )
    )
    slo_url: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_SLO_URL",
            "https://npm-scan.io/api/v1/sso/slo"
        )
    )

    # IdP metadata (discovery)
    idp_metadata_url: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_METADATA_URL",
            ""
        )
    )
    idp_metadata_xml: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_METADATA_XML",
            ""
        )
    )
    idp_entity_id: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_ENTITY_ID",
            ""
        )
    )
    idp_sso_url: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_SSO_URL",
            ""
        )
    )
    idp_slo_url: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_SLO_URL",
            ""
        )
    )
    idp_x509_cert: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_IDP_X509_CERT",
            ""
        )
    )

    # SP private key for decryption + signing
    sp_private_key: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_SP_PRIVATE_KEY",
            ""
        )
    )
    sp_x509_cert: str = field(
        default_factory=lambda: os.environ.get(
            "SAML_SP_X509_CERT",
            ""
        )
    )

    # Security settings
    want_assertions_signed: bool = True
    want_response_signed: bool = True
    want_assertions_encrypted: bool = False
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    digest_algorithm: str = "http://www.w3.org/2001/04/xmlenc#sha256"

    # User provisioning
    auto_provision: bool = True
    default_role: str = "viewer"
    admin_domains: list[str] = field(default_factory=list)
    attribute_mapping: dict[str, str] = field(default_factory=lambda: {
        "email": "email",
        "name": "displayName",
        "firstName": "firstName",
        "lastName": "lastName",
        "groups": "groups",
        "role": "Role",
    })

    # Session
    session_duration_hours: int = 24

    def to_onelogin_settings(self) -> dict:
        """Convert to python3-saml settings dict."""
        settings = {
            "strict": True,
            "debug": os.environ.get("SAML_DEBUG", "false").lower() == "true",
            "sp": {
                "entityId": self.entity_id,
                "assertionConsumerService": {
                    "url": self.acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url": self.slo_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "x509cert": self.sp_x509_cert or "",
                "privateKey": self.sp_private_key or "",
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "singleLogoutService": {
                    "url": self.idp_slo_url or self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.idp_x509_cert,
            },
            "security": {
                "wantAssertionsSigned": self.want_assertions_signed,
                "wantResponseSigned": self.want_response_signed,
                "wantAssertionsEncrypted": self.want_assertions_encrypted,
                "signatureAlgorithm": self.signature_algorithm,
                "digestAlgorithm": self.digest_algorithm,
                "nameIdEncrypted": False,
                "authnRequestsSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
                "signMetadata": bool(self.sp_private_key),
                "requestedAuthnContext": True,
            },
        }
        return settings

    def is_configured(self) -> bool:
        """Check if SAML has enough config to operate."""
        return bool(self.idp_sso_url and self.idp_entity_id) or bool(self.idp_metadata_url or self.idp_metadata_xml)


# Global singleton
_config: Optional[SAMLConfig] = None


def get_saml_config() -> SAMLConfig:
    global _config
    if _config is None:
        _config = SAMLConfig()
    return _config


def set_saml_config(cfg: SAMLConfig) -> None:
    global _config
    _config = cfg
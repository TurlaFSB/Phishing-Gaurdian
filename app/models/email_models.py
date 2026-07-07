"""
============================================================================
PHISHING GUARDIAN — EMAIL DATA MODELS
============================================================================
Pydantic models for parsed email data with comprehensive validation.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import re


# ---------------------------------------------------------------------------
# ENUMS
# ---------------------------------------------------------------------------
class AuthResult(str, Enum):
    """Email authentication results."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk classification levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# ATTACHMENT MODEL
# ---------------------------------------------------------------------------
class Attachment(BaseModel):
    """Email attachment metadata."""
    filename: str = Field(default="", description="Original filename")
    content_type: str = Field(default="application/octet-stream", description="MIME type")
    size: int = Field(default=0, description="Size in bytes", ge=0)
    md5_hash: Optional[str] = Field(default=None, description="MD5 hash of file content")
    sha256_hash: Optional[str] = Field(default=None, description="SHA256 hash of file content")
    extension: str = Field(default="", description="File extension extracted from filename")
    is_executable: bool = Field(default=False, description="Whether file is potentially executable")
    is_archive: bool = Field(default=False, description="Whether file is an archive format")
    
    @field_validator("extension", mode="before")
    @classmethod
    def extract_extension(cls, v: str, info: Any) -> str:
        """Extract extension from filename if not provided."""
        if not v and info.data.get("filename"):
            filename = info.data["filename"]
            if "." in filename:
                return filename.rsplit(".", 1)[-1].lower()
        return v.lower() if v else ""


# ---------------------------------------------------------------------------
# URL MODEL
# ---------------------------------------------------------------------------
class URLInfo(BaseModel):
    """Extracted URL with analysis results."""
    url: str = Field(..., description="Full URL as found in email")
    domain: str = Field(default="", description="Extracted domain")
    scheme: str = Field(default="http", description="URL scheme (http/https/ftp)")
    port: Optional[int] = Field(default=None, description="Port if specified")
    path: str = Field(default="", description="URL path")
    query_string: str = Field(default="", description="Query parameters")
    is_shortened: bool = Field(default=False, description="Whether URL uses a shortening service")
    is_ip_based: bool = Field(default=False, description="Whether URL uses IP instead of domain")
    has_suspicious_tld: bool = Field(default=False, description="Whether TLD is suspicious")
    
    # Analysis results (populated by integration modules)
    virustotal_result: Optional[Dict[str, Any]] = Field(default=None)
    urlscan_result: Optional[Dict[str, Any]] = Field(default=None)
    phishtank_result: Optional[Dict[str, Any]] = Field(default=None)
    risk_score: int = Field(default=0, ge=0, le=100, description="URL risk score (0-100)")


# ---------------------------------------------------------------------------
# HEADER ANALYSIS MODEL
# ---------------------------------------------------------------------------
class HeaderAnalysis(BaseModel):
    """Email header security analysis."""
    spf: AuthResult = Field(default=AuthResult.UNKNOWN, description="SPF authentication result")
    dkim: AuthResult = Field(default=AuthResult.UNKNOWN, description="DKIM authentication result")
    dmarc: AuthResult = Field(default=AuthResult.UNKNOWN, description="DMARC authentication result")
    
    reply_to_mismatch: bool = Field(default=False, description="Reply-To differs from From domain")
    sender_spoofed: bool = Field(default=False, description="Display name spoofing detected")
    received_chain_suspicious: bool = Field(default=False, description="Suspicious Received headers")
    has_urgency_language: bool = Field(default=False, description="Contains urgent/suspicious keywords")
    has_generic_greeting: bool = Field(default=False, description="Uses generic greeting (Dear Customer)")
    
    suspicious_indicators: List[str] = Field(default_factory=list, description="Detected issues")


# ---------------------------------------------------------------------------
# PARSED EMAIL MODEL
# ---------------------------------------------------------------------------
class ParsedEmail(BaseModel):
    """Complete parsed email with all extracted indicators."""
    
    # Identifiers
    analysis_id: str = Field(default="", description="Unique analysis ID")
    
    # Basic headers
    subject: str = Field(default="", description="Email subject")
    sender: str = Field(default="", description="From address")
    sender_display_name: str = Field(default="", description="Display name from From header")
    sender_domain: str = Field(default="", description="Domain extracted from sender")
    reply_to: str = Field(default="", description="Reply-To address")
    return_path: str = Field(default="", description="Return-Path address")
    date: str = Field(default="", description="Email date string")
    message_id: str = Field(default="", description="Message-ID header")
    
    # Recipients
    recipients: List[str] = Field(default_factory=list, description="To addresses")
    cc: List[str] = Field(default_factory=list, description="CC addresses")
    bcc: List[str] = Field(default_factory=list, description="BCC addresses (if detectable)")
    
    # Body
    body_text: str = Field(default="", description="Plain text body")
    body_html: str = Field(default="", description="HTML body")
    body_preview: str = Field(default="", description="First 500 chars of body for preview")
    
    # Extracted indicators
    urls: List[URLInfo] = Field(default_factory=list, description="Extracted URLs")
    ip_addresses: List[str] = Field(default_factory=list, description="Extracted IP addresses")
    domains: List[str] = Field(default_factory=list, description="Unique domains from URLs and emails")
    email_addresses: List[str] = Field(default_factory=list, description="All email addresses found")
    
    # Attachments
    attachments: List[Attachment] = Field(default_factory=list, description="Email attachments")
    total_attachments_size: int = Field(default=0, description="Total size of all attachments")
    
    # Headers
    received_chain: List[str] = Field(default_factory=list, description="Received header chain")
    header_analysis: HeaderAnalysis = Field(default_factory=HeaderAnalysis, description="Security analysis")
    
    # Raw data
    raw_headers: str = Field(default="", description="Complete raw headers")
    body_hashes: Dict[str, str] = Field(default_factory=dict, description="SHA256 hashes of body parts")
    
    # Metadata
    parsed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Parsing timestamp")
    email_size: int = Field(default=0, description="Total email size in bytes")


# ---------------------------------------------------------------------------
# ANALYSIS REQUEST/RESPONSE MODELS
# ---------------------------------------------------------------------------
class AnalysisRequest(BaseModel):
    """Request model for email analysis."""
    raw_email: Optional[str] = Field(default=None, description="Raw email text with headers")
    email_base64: Optional[str] = Field(default=None, description="Base64-encoded email file")

    @field_validator("raw_email")
    @classmethod
    def validate_raw_email(cls, v: Optional[str], info: Any) -> Optional[str]:
        """Validate that at least one input is provided."""
        email_base64 = info.data.get("email_base64")
        if not v and not email_base64:
            raise ValueError("Either 'raw_email' or 'email_base64' must be provided")
        return v


class AnalysisResponse(BaseModel):
    """Complete analysis response."""
    analysis_id: str = Field(..., description="Unique analysis ID")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Email summary
    subject: str = Field(default="")
    sender: str = Field(default="")
    sender_domain: str = Field(default="")
    date: str = Field(default="")
    urls_found: int = Field(default=0)
    attachments_found: int = Field(default=0)
    
    # Risk
    overall_risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel = Field(default=RiskLevel.SAFE)
    summary: str = Field(default="")
    
    # Detailed
    header_analysis: HeaderAnalysis = Field(default_factory=HeaderAnalysis)
    urls: List[URLInfo] = Field(default_factory=list)
    suspicious_indicators: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    sources_checked: List[str] = Field(default_factory=list)
    analysis_time_seconds: float = Field(default=0.0)
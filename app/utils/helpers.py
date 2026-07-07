"""
============================================================================
PHISHING GUARDIAN — HELPER UTILITIES
============================================================================

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import re
import hashlib
import base64
from typing import Optional
from urllib.parse import urlparse, urlunparse


def clean_url(url: str) -> str:
    """Clean and normalize a URL."""
    url = url.strip().rstrip(".,;:!?\"'<>\\")
    
    # Add scheme if missing
    if not url.startswith(("http://", "https://", "ftp://")):
        if url.startswith("www."):
            url = "http://" + url
        elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url):
            url = "http://" + url
    
    # Normalize
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        
        # Remove default ports
        if (parsed.scheme == "http" and parsed.port == 80) or \
           (parsed.scheme == "https" and parsed.port == 443):
            netloc = netloc.rsplit(":", 1)[0]
        
        return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, ""))
    except Exception:
        return url


def is_ip_address(text: str) -> bool:
    """Check if text is a valid IP address (v4 or v6)."""
    # IPv4
    ipv4_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    if ipv4_pattern.match(text):
        parts = text.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    
    # IPv6 (simplified)
    ipv6_pattern = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv6_pattern.match(text))


def extract_email_addresses(text: str) -> list:
    """Extract all email addresses from text."""
    pattern = re.compile(
        r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+'
        r'@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
    )
    return pattern.findall(text)


def compute_hashes(data: bytes) -> dict:
    """Compute MD5 and SHA256 hashes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("utf-8")


def decode_base64(data: str) -> Optional[bytes]:
    """Decode base64 string to bytes."""
    try:
        return base64.b64decode(data)
    except Exception:
        return None


def generate_id(prefix: str = "") -> str:
    """Generate a unique ID with optional prefix."""
    import uuid
    uid = str(uuid.uuid4())[:12]
    return f"{prefix}_{uid}" if prefix else uid
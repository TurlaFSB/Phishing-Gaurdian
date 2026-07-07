"""
============================================================================
PHISHING GUARDIAN — INTEGRATIONS PACKAGE
============================================================================
Exports all integration classes for easy import.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from app.integrations.virustotal import VirusTotalIntegration
from app.integrations.urlscan import URLScanIntegration
from app.integrations.abuseipdb import AbuseIPDBIntegration
from app.integrations.phishtank import PhishTankIntegration
from app.integrations.openphish import OpenPhishIntegration
from app.integrations.whois_lookup import WhoisIntegration

__all__ = [
    "VirusTotalIntegration",
    "URLScanIntegration",
    "AbuseIPDBIntegration",
    "PhishTankIntegration",
    "OpenPhishIntegration",
    "WhoisIntegration",
]
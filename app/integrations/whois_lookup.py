"""
============================================================================
PHISHING GUARDIAN — WHOIS INTEGRATION
============================================================================
COMPLETELY FREE — Uses python-whois library. No API key required.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
import logging
from datetime import datetime
from typing import Dict, Any

import whois

from app.integrations.base import BaseIntegration, IntegrationResult

logger = logging.getLogger(__name__)


class WhoisIntegration(BaseIntegration):
    """WHOIS domain lookup — completely free, no API key needed."""
    
    @property
    def source_name(self) -> str:
        return "whois"
    
    @property
    def is_available(self) -> bool:
        return True
    
    async def check_domain(self, domain: str) -> IntegrationResult:
        """Look up domain registration information."""
        start = time.time()
        
        try:
            # Clean domain
            domain = domain.lower().strip()
            if domain.startswith("www."):
                domain = domain[4:]
            
            # Run WHOIS lookup in a thread (it's synchronous)
            import asyncio
            w = await asyncio.to_thread(whois.whois, domain)
            
            # Parse creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Parse expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            # Calculate domain age
            age_days = 0
            if creation_date:
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
            
            # Calculate days until expiry
            days_until_expiry = 0
            if expiration_date and isinstance(expiration_date, datetime):
                days_until_expiry = (expiration_date - datetime.now()).days
            
            # Suspicious indicators
            indicators = []
            if 0 < age_days < 30:
                indicators.append(f"Domain registered only {age_days} days ago")
            if days_until_expiry < 90:
                indicators.append(f"Domain expires in {days_until_expiry} days")
            
            # Risk score based on age
            risk_score = 0
            if age_days == 0:
                risk_score = 30  # Unknown age
            elif age_days < 7:
                risk_score = 90  # Very new
            elif age_days < 30:
                risk_score = 60  # New
            elif age_days < 180:
                risk_score = 30  # Somewhat new
            elif age_days < 365:
                risk_score = 15  # Established
            else:
                risk_score = 5   # Well-established
            
            return IntegrationResult(
                source=self.source_name,
                success=True,
                data={
                    "domain": domain,
                    "registrar": str(w.registrar) if w.registrar else "Unknown",
                    "creation_date": str(creation_date) if creation_date else "Unknown",
                    "expiration_date": str(expiration_date) if expiration_date else "Unknown",
                    "age_days": age_days,
                    "days_until_expiry": days_until_expiry,
                    "name_servers": [str(ns) for ns in (w.name_servers or [])],
                    "country": str(w.country) if w.country else "Unknown",
                    "registrant_organization": str(w.org) if w.org else "",
                    "suspicious_indicators": indicators,
                    "risk_score": risk_score,
                },
                response_time_ms=(time.time() - start) * 1000
            )
            
        except whois.parser.PywhoisError:
            return IntegrationResult(
                source=self.source_name,
                success=True,
                data={
                    "domain": domain,
                    "error": "Domain not found or not registered",
                    "risk_score": 70,  # Unregistered or unavailable = suspicious
                },
                response_time_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
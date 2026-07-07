"""
============================================================================
PHISHING GUARDIAN — ABUSEIPDB INTEGRATION
============================================================================
Free tier: 1000 IP checks per day

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
import logging

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBIntegration(BaseIntegration):
    """AbuseIPDB API v2 integration."""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    @property
    def source_name(self) -> str:
        return "abuseipdb"
    
    @property
    def is_available(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)
    
    async def check_url(self, url: str) -> IntegrationResult:
        """AbuseIPDB does not support URL checking."""
        return IntegrationResult(
            source=self.source_name,
            success=False,
            error="URL checking not supported by AbuseIPDB — use IP checking"
        )
    
    async def check_ip(self, ip: str) -> IntegrationResult:
        """Check IP reputation against AbuseIPDB."""
        start = time.time()
        
        if not self.is_available:
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error="AbuseIPDB API key not configured"
            )
        
        try:
            headers = {
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": True
                    }
                )
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    
                    return IntegrationResult(
                        source=self.source_name,
                        success=True,
                        data={
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "last_reported_at": data.get("lastReportedAt", ""),
                            "country": data.get("countryName", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "domain": data.get("domain", ""),
                            "usage_type": data.get("usageType", ""),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "risk_score": data.get("abuseConfidenceScore", 0),
                        },
                        response_time_ms=(time.time() - start) * 1000
                    )
                
                return IntegrationResult(
                    source=self.source_name,
                    success=False,
                    error=f"API error: HTTP {response.status_code}"
                )
                
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
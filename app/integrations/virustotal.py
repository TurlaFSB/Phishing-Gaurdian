"""
============================================================================
PHISHING GUARDIAN — VIRUSTOTAL INTEGRATION
============================================================================
Free tier: 500 requests/day, 4 requests/minute

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import asyncio
import time
import logging
from typing import Dict, Any

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class VirusTotalIntegration(BaseIntegration):
    """VirusTotal API v3 integration."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    @property
    def source_name(self) -> str:
        return "virustotal"
    
    @property
    def is_available(self) -> bool:
        return bool(settings.VT_API_KEY)
    
    async def check_url(self, url: str) -> IntegrationResult:
        """Submit URL to VirusTotal and retrieve analysis."""
        start = time.time()
        
        if not self.is_available:
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error="VirusTotal API key not configured",
                response_time_ms=(time.time() - start) * 1000
            )
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "x-apikey": settings.VT_API_KEY,
                    "Accept": "application/json"
                }
                
                # Submit URL
                response = await client.post(
                    f"{self.BASE_URL}/urls",
                    headers=headers,
                    data={"url": url}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data.get("data", {}).get("id", "")
                    
                    # Wait for analysis to complete
                    await asyncio.sleep(3)
                    
                    # Retrieve analysis
                    analysis_resp = await client.get(
                        f"{self.BASE_URL}/analyses/{analysis_id}",
                        headers=headers
                    )
                    
                    if analysis_resp.status_code == 200:
                        analysis_data = analysis_resp.json()
                        attributes = analysis_data.get("data", {}).get("attributes", {})
                        stats = attributes.get("stats", {})
                        
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        harmless = stats.get("harmless", 0)
                        undetected = stats.get("undetected", 0)
                        total = sum(stats.values()) or 1
                        
                        risk_score = int(((malicious * 100) + (suspicious * 50)) / total)
                        
                        return IntegrationResult(
                            source=self.source_name,
                            success=True,
                            data={
                                "malicious": malicious,
                                "suspicious": suspicious,
                                "harmless": harmless,
                                "undetected": undetected,
                                "total_engines": total,
                                "risk_score": min(100, risk_score),
                                "analysis_id": analysis_id,
                            },
                            response_time_ms=(time.time() - start) * 1000
                        )
                
                elif response.status_code == 429:
                    return IntegrationResult(
                        source=self.source_name,
                        success=False,
                        error="Rate limit exceeded — try again later",
                        response_time_ms=(time.time() - start) * 1000
                    )
                
                return IntegrationResult(
                    source=self.source_name,
                    success=False,
                    error=f"API error: HTTP {response.status_code}",
                    response_time_ms=(time.time() - start) * 1000
                )
                
        except httpx.TimeoutException:
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error="Request timed out",
                response_time_ms=(time.time() - start) * 1000
            )
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e),
                response_time_ms=(time.time() - start) * 1000
            )
    
    async def check_hash(self, file_hash: str) -> IntegrationResult:
        """Check a file hash against VirusTotal database."""
        start = time.time()
        
        if not self.is_available:
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error="VirusTotal API key not configured"
            )
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                headers = {
                    "x-apikey": settings.VT_API_KEY,
                    "Accept": "application/json"
                }
                
                response = await client.get(
                    f"{self.BASE_URL}/files/{file_hash}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    
                    return IntegrationResult(
                        source=self.source_name,
                        success=True,
                        data={
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total_engines": total,
                            "risk_score": min(100, int((malicious * 100) / total)),
                            "file_name": attributes.get("meaningful_name", "Unknown"),
                        },
                        response_time_ms=(time.time() - start) * 1000
                    )
                
                return IntegrationResult(
                    source=self.source_name,
                    success=False,
                    error="File not found in VirusTotal database",
                    response_time_ms=(time.time() - start) * 1000
                )
                
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
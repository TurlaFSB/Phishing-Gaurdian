"""
============================================================================
PHISHING GUARDIAN — URLSCAN.IO INTEGRATION
============================================================================
Free tier: Works WITHOUT API key (unauthenticated scans)

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
import logging
from typing import Dict, Any

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class URLScanIntegration(BaseIntegration):
    """URLScan.io integration — completely free, no API key required."""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    @property
    def source_name(self) -> str:
        return "urlscan"
    
    @property
    def is_available(self) -> bool:
        return True  # Always available — no key needed
    
    async def check_url(self, url: str) -> IntegrationResult:
        """Submit URL to URLScan.io for analysis."""
        start = time.time()
        
        try:
            headers = {"Content-Type": "application/json"}
            if settings.URLSCAN_API_KEY:
                headers["API-Key"] = settings.URLSCAN_API_KEY
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/scan/",
                    headers=headers,
                    json={
                        "url": url,
                        "visibility": "unlisted",
                        "tags": ["phishing-guardian"]
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    scan_id = data.get("uuid", "")
                    
                    return IntegrationResult(
                        source=self.source_name,
                        success=True,
                        data={
                            "scan_id": scan_id,
                            "status": "submitted",
                            "result_url": f"https://urlscan.io/result/{scan_id}/",
                        },
                        response_time_ms=(time.time() - start) * 1000
                    )
                
                elif response.status_code == 429:
                    return IntegrationResult(
                        source=self.source_name,
                        success=False,
                        error="Rate limit reached — try again later",
                        response_time_ms=(time.time() - start) * 1000
                    )
                
                return IntegrationResult(
                    source=self.source_name,
                    success=False,
                    error=f"URLScan error: HTTP {response.status_code}",
                    response_time_ms=(time.time() - start) * 1000
                )
                
        except httpx.TimeoutException:
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error="Request timed out"
            )
        except Exception as e:
            logger.error(f"URLScan error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
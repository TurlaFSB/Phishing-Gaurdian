"""
============================================================================
PHISHING GUARDIAN — OPENPHISH INTEGRATION
============================================================================
COMPLETELY FREE — AI-detected phishing URLs. No API key required.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
import logging
from typing import List

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class OpenPhishIntegration(BaseIntegration):
    """OpenPhish integration — completely free, AI-powered phishing detection."""
    
    @property
    def source_name(self) -> str:
        return "openphish"
    
    @property
    def is_available(self) -> bool:
        return True
    
    def __init__(self):
        self._urls: List[str] = []
        self._last_update: float = 0
        self._cache_ttl: int = 1800  # 30 minutes
    
    async def _get_phishing_urls(self) -> List[str]:
        """Fetch current phishing URLs from OpenPhish."""
        current_time = time.time()
        
        if self._urls and (current_time - self._last_update) < self._cache_ttl:
            return self._urls
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(settings.OPENPHISH_URL)
                
                if response.status_code == 200:
                    self._urls = [
                        line.strip()
                        for line in response.text.split("\n")
                        if line.strip() and line.strip().startswith("http")
                    ]
                    self._last_update = current_time
                    logger.info(f"OpenPhish updated: {len(self._urls)} URLs")
                    return self._urls
        except Exception as e:
            logger.warning(f"OpenPhish update failed: {e}")
        
        return self._urls
    
    async def check_url(self, url: str) -> IntegrationResult:
        """Check if URL is in OpenPhish feed."""
        start = time.time()
        
        try:
            phishing_urls = await self._get_phishing_urls()
            
            url_clean = url.rstrip("/").lower()
            for phishing_url in phishing_urls:
                if url_clean in phishing_url.lower() or phishing_url.lower() in url_clean:
                    return IntegrationResult(
                        source=self.source_name,
                        success=True,
                        data={
                            "found": True,
                            "risk_score": 85,
                        },
                        response_time_ms=(time.time() - start) * 1000
                    )
            
            return IntegrationResult(
                source=self.source_name,
                success=True,
                data={
                    "found": False,
                    "risk_score": 0,
                },
                response_time_ms=(time.time() - start) * 1000
            )
            
        except Exception as e:
            logger.error(f"OpenPhish check error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
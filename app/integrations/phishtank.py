"""
============================================================================
PHISHING GUARDIAN — PHISHTANK INTEGRATION
============================================================================
COMPLETELY FREE — No API key required. Community phishing database.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import time
import logging
from typing import Dict, List, Optional

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class PhishTankIntegration(BaseIntegration):
    """PhishTank integration — completely free, no API key needed."""
    
    @property
    def source_name(self) -> str:
        return "phishtank"
    
    @property
    def is_available(self) -> bool:
        return True
    
    def __init__(self):
        self._cache: List[Dict] = []
        self._last_update: float = 0
        self._cache_ttl: int = 3600  # 1 hour
    
    async def _get_phishing_data(self) -> List[Dict]:
        """Fetch current phishing data from PhishTank."""
        current_time = time.time()
        
        if self._cache and (current_time - self._last_update) < self._cache_ttl:
            return self._cache
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(settings.PHISHTANK_URL)
                
                if response.status_code == 200:
                    self._cache = response.json()
                    self._last_update = current_time
                    logger.info(f"PhishTank cache updated: {len(self._cache)} entries")
                    return self._cache
        except Exception as e:
            logger.warning(f"PhishTank update failed: {e}")
        
        return self._cache
    
    async def check_url(self, url: str) -> IntegrationResult:
        """Check if URL is in PhishTank database."""
        start = time.time()
        
        try:
            phishing_data = await self._get_phishing_data()
            
            for entry in phishing_data:
                if url in entry.get("url", ""):
                    return IntegrationResult(
                        source=self.source_name,
                        success=True,
                        data={
                            "found": True,
                            "verified": entry.get("verified", False),
                            "verified_at": entry.get("verified_time", ""),
                            "phish_id": entry.get("phish_id", ""),
                            "phish_detail_url": entry.get("phish_detail_url", ""),
                            "risk_score": 80 if entry.get("verified") else 50,
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
            logger.error(f"PhishTank check error: {e}")
            return IntegrationResult(
                source=self.source_name,
                success=False,
                error=str(e)
            )
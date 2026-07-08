"""
============================================================================
PHISHING GUARDIAN — PHISHTANK INTEGRATION
============================================================================
COMPLETELY FREE — No API key required. Community phishing database.

Author:  Dr. Erik
Version: 1.1.0 (hardened)
============================================================================
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import httpx

from app.integrations.base import BaseIntegration, IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


def _normalize_url(url: str) -> str:
    """Normalize a URL for comparison: lowercase scheme/host, drop a
    trailing slash, keep path/query as-is. Used so matching is an exact
    comparison rather than a substring check (substring checks against a
    lookalike-domain database are exploitable — a clean URL that happens
    to be a text prefix of a malicious one would otherwise be flagged)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/").lower() or ""
        normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
        return normalized
    except Exception:
        return url.strip().lower()


def _is_verified(value) -> bool:
    """PhishTank's feed format for the 'verified' field is not guaranteed
    to be a Python bool — some feed formats use the string 'yes'/'no'. A
    naive `if entry.get('verified')` treats the string 'no' as truthy
    (non-empty string), silently marking every entry as verified. Handle
    both representations explicitly rather than assuming one."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1")
    return False


class PhishTankIntegration(BaseIntegration):
    """PhishTank integration — completely free, no API key needed."""

    @property
    def source_name(self) -> str:
        return "phishtank"

    @property
    def is_available(self) -> bool:
        return bool(getattr(settings, "PHISHTANK_URL", None))

    def __init__(self):
        super().__init__()
        self._cache: List[Dict] = []
        self._url_index: Dict[str, Dict] = {}
        self._last_update: float = 0
        self._cache_ttl: int = 3600  # 1 hour
        self._refresh_lock = asyncio.Lock()

    async def _get_phishing_data(self) -> List[Dict]:
        """Fetch current phishing data from PhishTank, rebuilding the
        lookup index. Guarded by a lock so concurrent requests don't
        trigger duplicate simultaneous fetches of the (large) feed."""
        current_time = time.time()

        if self._cache and (current_time - self._last_update) < self._cache_ttl:
            return self._cache

        async with self._refresh_lock:
            # Re-check after acquiring the lock — another coroutine may have
            # already refreshed the cache while we were waiting for it.
            current_time = time.time()
            if self._cache and (current_time - self._last_update) < self._cache_ttl:
                return self._cache

            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(settings.PHISHTANK_URL)

                    if response.status_code == 200:
                        data = response.json()
                        if not isinstance(data, list):
                            logger.error(
                                f"PhishTank returned unexpected data shape: {type(data)}"
                            )
                            return self._cache
                        self._cache = data
                        self._url_index = self._build_index(data)
                        self._last_update = current_time
                        logger.info(f"PhishTank cache updated: {len(self._cache)} entries")
                        return self._cache
                    else:
                        logger.warning(
                            f"PhishTank update failed: HTTP {response.status_code}"
                        )
            except Exception as e:
                logger.warning(f"PhishTank update failed: {e}")

            return self._cache

    def _build_index(self, entries: List[Dict]) -> Dict[str, Dict]:
        """Build an O(1) lookup index keyed by normalized URL, instead of
        doing a linear substring scan per check — matters once the feed
        has tens of thousands of entries."""
        index: Dict[str, Dict] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw_url = entry.get("url", "")
            if not raw_url:
                continue
            index[_normalize_url(raw_url)] = entry
        return index

    async def check_url(self, url: str) -> IntegrationResult:
        """Check if URL is in PhishTank database (exact match on
        normalized URL, not substring containment)."""
        start = time.time()

        try:
            await self._get_phishing_data()
            normalized = _normalize_url(url)
            entry = self._url_index.get(normalized)

            if entry:
                verified = _is_verified(entry.get("verified", False))
                return IntegrationResult(
                    source=self.source_name,
                    success=True,
                    data={
                        "found": True,
                        "verified": verified,
                        "verified_at": entry.get("verification_time", entry.get("verified_time", "")),
                        "phish_id": entry.get("phish_id", ""),
                        "phish_detail_url": entry.get("phish_detail_url", ""),
                        "risk_score": 80 if verified else 50,
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
                error=str(e),
                response_time_ms=(time.time() - start) * 1000
            )
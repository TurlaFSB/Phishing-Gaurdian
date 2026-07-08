"""
============================================================================
PHISHING GUARDIAN — ANALYSIS ORCHESTRATOR
============================================================================
Coordinates all threat intelligence integrations.
Runs API checks in parallel with smart caching and rate limiting.

Author:  Dr. Erik
Version: 1.1.0 — bug fixes: removed cross-request shared state race,
         real per-item parallelism (was sequential-per-URL despite the
         docstring), TTL'd cache that still counts on cache hits, global
         concurrency semaphore + per-call timeout, exception logging,
         attachment count cap for consistency with url/ip/domain limits.
============================================================================
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Set, Optional

from app.models.email_models import ParsedEmail, URLInfo, Attachment
from app.integrations import (
    VirusTotalIntegration,
    URLScanIntegration,
    AbuseIPDBIntegration,
    PhishTankIntegration,
    OpenPhishIntegration,
    WhoisIntegration,
)
from app.integrations.base import IntegrationResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Orchestrates all threat intelligence checks against a parsed email.

    Features:
    - Parallel async API calls (across BOTH items and integrations)
    - TTL'd caching to avoid redundant checks without serving stale data
    - Graceful degradation when APIs are unavailable, slow, or erroring
    - A shared semaphore bounding total concurrent outbound API calls
    """

    def __init__(self):
        """Initialize all integration modules."""
        self.integrations = {
            "virustotal": VirusTotalIntegration(),
            "urlscan": URLScanIntegration(),
            "abuseipdb": AbuseIPDBIntegration(),
            "phishtank": PhishTankIntegration(),
            "openphish": OpenPhishIntegration(),
            "whois": WhoisIntegration(),
        }

        # FIX (v1.1.0): "sources checked" used to live on `self` and get
        # reset at the top of analyze(). Since this engine can be reused
        # (e.g. as a FastAPI singleton dependency), two concurrent requests
        # would race on that attribute and could leak each other's data.
        # It is now a local variable inside analyze() instead — see below.

        # Shared URL cache: (cached_at_epoch_seconds, result_dict).
        # FIX (v1.1.0): entries now carry a timestamp and expire via
        # URL_CACHE_TTL_SECONDS instead of living forever, so a transient
        # API outage doesn't permanently poison results for a URL.
        self._url_cache: Dict[str, "tuple[float, Dict]"] = {}

        # FIX (v1.1.0): a single semaphore shared across every outbound
        # integration call (URLs, IPs, domains, attachments) actually
        # implements the "rate limit awareness" the class docstring
        # promised but never enforced.
        self._api_semaphore = asyncio.Semaphore(
            getattr(settings, "MAX_CONCURRENT_API_CALLS", 8)
        )

    async def analyze(self, parsed_email: ParsedEmail) -> Dict[str, Any]:
        """
        Run complete analysis on a parsed email.

        Args:
            parsed_email: ParsedEmail object from the parser

        Returns:
            Dict containing all analysis results
        """
        start_time = time.time()
        sources_checked: Set[str] = set()  # local — see FIX note in __init__

        tasks = []
        labels = []

        if parsed_email.urls:
            tasks.append(self._analyze_urls(parsed_email.urls))
            labels.append("urls")
        if parsed_email.ip_addresses:
            tasks.append(self._analyze_ips(parsed_email.ip_addresses))
            labels.append("ips")
        if parsed_email.domains:
            tasks.append(self._analyze_domains(parsed_email.domains))
            labels.append("domains")
        if parsed_email.attachments:
            tasks.append(self._analyze_attachments(parsed_email.attachments))
            labels.append("attachments")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        url_results: List[Dict] = []
        ip_results: List[Dict] = []
        domain_results: List[Dict] = []
        attachment_results: List[Dict] = []

        # FIX (v1.1.0): results are now matched to their category by
        # position (tasks/labels were built together, so they line up),
        # and exceptions are logged instead of being silently dropped by
        # the old `isinstance(result, dict)` filter.
        for label, result in zip(labels, results):
            if isinstance(result, Exception):
                logger.error(f"Analysis category '{label}' failed: {result}", exc_info=result)
                continue
            if label == "urls":
                url_results = result["url_checks"]
                sources_checked.update(result.get("sources", []))
            elif label == "ips":
                ip_results = result["ip_checks"]
                sources_checked.update(result.get("sources", []))
            elif label == "domains":
                domain_results = result["domain_checks"]
                sources_checked.update(result.get("sources", []))
            elif label == "attachments":
                attachment_results = result["attachment_checks"]
                sources_checked.update(result.get("sources", []))

        analysis_time = round(time.time() - start_time, 2)

        return {
            "urls": url_results,
            "ips": ip_results,
            "domains": domain_results,
            "attachments": attachment_results,
            "sources_checked": list(sources_checked),
            "analysis_time_seconds": analysis_time,
            "integrations_available": sum(
                1 for integration in self.integrations.values()
                if integration.is_available
            ),
        }

    # -------------------------------------------------------------------
    # SAFE CALL WRAPPER — timeout + exception handling + rate limiting
    # -------------------------------------------------------------------
    async def _safe_call(self, coro, source_name: str, target: str) -> Optional[IntegrationResult]:
        """
        Runs a single integration coroutine under the shared concurrency
        semaphore with a timeout. Returns None (and logs) on timeout or
        error instead of letting either crash the batch silently.
        """
        timeout = getattr(settings, "INTEGRATION_TIMEOUT_SECONDS", 12)
        async with self._api_semaphore:
            try:
                return await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning(f"{source_name} timed out checking '{target}' (>{timeout}s)")
                return None
            except Exception as e:
                logger.warning(f"{source_name} raised an error checking '{target}': {e}")
                return None

    # -------------------------------------------------------------------
    # CACHE HELPERS
    # -------------------------------------------------------------------
    def _cache_get(self, key: str) -> Optional[Dict]:
        entry = self._url_cache.get(key)
        if not entry:
            return None
        cached_at, value = entry
        ttl = getattr(settings, "URL_CACHE_TTL_SECONDS", 300)
        if time.time() - cached_at > ttl:
            self._url_cache.pop(key, None)
            return None
        return value

    def _cache_set(self, key: str, value: Dict) -> None:
        self._url_cache[key] = (time.time(), value)

    @staticmethod
    def _cached_success_sources(cached_result: Dict) -> Set[str]:
        """FIX (v1.1.0): a cache hit used to contribute nothing to
        sources_checked even though the cached payload has the same
        per-source success data as a fresh lookup. Extract it here so
        confidence scoring doesn't degrade just because a URL was seen
        before."""
        return {
            name for name, res in cached_result.get("sources", {}).items()
            if isinstance(res, dict) and res.get("success")
        }

    # -------------------------------------------------------------------
    # URL ANALYSIS — fully parallel across URLs AND integrations
    # -------------------------------------------------------------------
    async def _analyze_urls(self, urls: List[URLInfo]) -> Dict:
        """
        FIX (v1.1.0): previously looped over URLs one at a time, only
        parallelizing the ~6 integrations *within* each URL. For an email
        with many links this meant N sequential round-trips. Now every
        (url, integration) pair is dispatched in a single gather, bounded
        globally by self._api_semaphore.
        """
        selected = urls[:settings.MAX_URLS_TO_ANALYZE]

        cached_map: Dict[int, Dict] = {}
        to_fetch: List["tuple[int, str]"] = []

        for i, url_info in enumerate(selected):
            cached = self._cache_get(url_info.url)
            if cached is not None:
                cached_map[i] = cached
            else:
                to_fetch.append((i, url_info.url))

        fetch_coros = []
        fetch_meta: List["tuple[int, str, str]"] = []
        for i, url in to_fetch:
            for name, integration in self.integrations.items():
                if integration.is_available:
                    fetch_coros.append(self._safe_call(integration.check_url(url), name, url))
                    fetch_meta.append((i, url, name))

        fetched = await asyncio.gather(*fetch_coros) if fetch_coros else []

        fresh_by_index: Dict[int, Dict] = {}
        sources: Set[str] = set()
        for (i, url, name), result in zip(fetch_meta, fetched):
            entry = fresh_by_index.setdefault(i, {"url": url, "sources": {}})
            if isinstance(result, IntegrationResult):
                entry["sources"][name] = result.to_dict()
                if result.success:
                    sources.add(name)

        url_checks: List[Dict] = []
        for i, url_info in enumerate(selected):
            if i in cached_map:
                result = cached_map[i]
                sources |= self._cached_success_sources(result)
            else:
                result = fresh_by_index.get(i, {"url": url_info.url, "sources": {}})
                self._cache_set(url_info.url, result)
            url_checks.append(result)

        return {"url_checks": url_checks, "sources": list(sources)}

    # -------------------------------------------------------------------
    # IP ANALYSIS — parallel across all IPs
    # -------------------------------------------------------------------
    async def _analyze_ips(self, ips: List[str]) -> Dict:
        abuseipdb = self.integrations.get("abuseipdb")
        if not abuseipdb or not abuseipdb.is_available:
            return {"ip_checks": [], "sources": []}

        selected = ips[:settings.MAX_IPS_TO_ANALYZE]
        results = await asyncio.gather(
            *(self._safe_call(abuseipdb.check_ip(ip), "abuseipdb", ip) for ip in selected)
        )

        sources: Set[str] = set()
        ip_checks = []
        for ip, result in zip(selected, results):
            if result is None:
                ip_checks.append({"ip": ip, "abuseipdb": {"error": "request failed or timed out"}})
                continue
            ip_checks.append({
                "ip": ip,
                "abuseipdb": result.to_dict() if result.success else {"error": result.error}
            })
            if result.success:
                sources.add("abuseipdb")

        return {"ip_checks": ip_checks, "sources": list(sources)}

    # -------------------------------------------------------------------
    # DOMAIN ANALYSIS — parallel across all domains
    # -------------------------------------------------------------------
    async def _analyze_domains(self, domains: List[str]) -> Dict:
        whois_integration = self.integrations.get("whois")
        if not whois_integration:
            return {"domain_checks": [], "sources": []}

        selected = domains[:settings.MAX_DOMAINS_TO_ANALYZE]
        results = await asyncio.gather(
            *(self._safe_call(whois_integration.check_domain(d), "whois", d) for d in selected)
        )

        sources: Set[str] = set()
        domain_checks = []
        for domain, result in zip(selected, results):
            if result is None:
                domain_checks.append({"domain": domain, "whois": {"error": "request failed or timed out"}})
                continue
            domain_checks.append({
                "domain": domain,
                "whois": result.to_dict() if result.success else {"error": result.error}
            })
            if result.success:
                sources.add("whois")

        return {"domain_checks": domain_checks, "sources": list(sources)}

    # -------------------------------------------------------------------
    # ATTACHMENT ANALYSIS — parallel, now capped like every other category
    # -------------------------------------------------------------------
    async def _analyze_attachments(self, attachments: List[Attachment]) -> Dict:
        vt = self.integrations.get("virustotal")
        if not vt or not vt.is_available:
            return {"attachment_checks": [], "sources": []}

        # FIX (v1.1.0): urls/ips/domains are all sliced by a MAX_*
        # setting; attachments previously had no cap, so an email with
        # many attachments could fire an unbounded number of VirusTotal
        # hash lookups. Now consistent with the other categories.
        max_attachments = getattr(settings, "MAX_ATTACHMENTS_TO_ANALYZE", 10)
        hashed = [a for a in attachments if a.sha256_hash][:max_attachments]

        results = await asyncio.gather(
            *(self._safe_call(vt.check_hash(a.sha256_hash), "virustotal", a.sha256_hash) for a in hashed)
        )

        sources: Set[str] = set()
        attachment_checks = []
        for att, result in zip(hashed, results):
            if result is None:
                attachment_checks.append({
                    "filename": att.filename,
                    "sha256": att.sha256_hash,
                    "size": att.size,
                    "virustotal": {"error": "request failed or timed out"}
                })
                continue
            attachment_checks.append({
                "filename": att.filename,
                "sha256": att.sha256_hash,
                "size": att.size,
                "virustotal": result.to_dict() if result.success else {"error": result.error}
            })
            if result.success:
                sources.add("virustotal")

        return {"attachment_checks": attachment_checks, "sources": list(sources)}
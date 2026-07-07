"""
============================================================================
PHISHING GUARDIAN — ANALYSIS ORCHESTRATOR
============================================================================
Coordinates all threat intelligence integrations.
Runs API checks in parallel with smart caching and rate limiting.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Set

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
    - Parallel async API calls
    - Smart caching to avoid redundant checks
    - Graceful degradation when APIs are unavailable
    - Rate limit awareness
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
        
        # Track which sources were actually used
        self.sources_checked: Set[str] = set()
        
        # Simple in-memory URL cache
        self._url_cache: Dict[str, Dict] = {}
    
    async def analyze(self, parsed_email: ParsedEmail) -> Dict[str, Any]:
        """
        Run complete analysis on a parsed email.
        
        Args:
            parsed_email: ParsedEmail object from the parser
            
        Returns:
            Dict containing all analysis results
        """
        start_time = time.time()
        self.sources_checked = set()
        
        # Prepare all analysis tasks
        tasks = []
        
        # URL analysis
        if parsed_email.urls:
            tasks.append(self._analyze_urls(parsed_email.urls))
        
        # IP analysis
        if parsed_email.ip_addresses:
            tasks.append(self._analyze_ips(parsed_email.ip_addresses))
        
        # Domain analysis
        if parsed_email.domains:
            tasks.append(self._analyze_domains(parsed_email.domains))
        
        # Attachment analysis
        if parsed_email.attachments:
            tasks.append(self._analyze_attachments(parsed_email.attachments))
        
        # Run all tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Organize results
        url_results = []
        ip_results = []
        domain_results = []
        attachment_results = []
        
        for result in results:
            if isinstance(result, dict):
                if "url_checks" in result:
                    url_results = result["url_checks"]
                    self.sources_checked.update(result.get("sources", []))
                elif "ip_checks" in result:
                    ip_results = result["ip_checks"]
                    self.sources_checked.update(result.get("sources", []))
                elif "domain_checks" in result:
                    domain_results = result["domain_checks"]
                    self.sources_checked.update(result.get("sources", []))
                elif "attachment_checks" in result:
                    attachment_results = result["attachment_checks"]
                    self.sources_checked.update(result.get("sources", []))
        
        analysis_time = round(time.time() - start_time, 2)
        
        return {
            "urls": url_results,
            "ips": ip_results,
            "domains": domain_results,
            "attachments": attachment_results,
            "sources_checked": list(self.sources_checked),
            "analysis_time_seconds": analysis_time,
            "integrations_available": sum(
                1 for integration in self.integrations.values()
                if integration.is_available
            ),
        }
    
    async def _analyze_urls(self, urls: List[URLInfo]) -> Dict:
        """Analyze all URLs with parallel API calls."""
        url_checks = []
        sources = set()
        
        for url_info in urls[:settings.MAX_URLS_TO_ANALYZE]:
            url = url_info.url
            
            # Check cache
            if url in self._url_cache:
                url_checks.append(self._url_cache[url])
                continue
            
            # Prepare checks for this URL
            url_tasks = []
            integration_names = []
            
            for name, integration in self.integrations.items():
                if integration.is_available:
                    url_tasks.append(integration.check_url(url))
                    integration_names.append(name)
            
            if not url_tasks:
                continue
            
            # Run all checks for this URL
            check_results = await asyncio.gather(*url_tasks, return_exceptions=True)
            
            url_result = {"url": url, "sources": {}}
            for i, result in enumerate(check_results):
                if isinstance(result, IntegrationResult):
                    url_result["sources"][integration_names[i]] = result.to_dict()
                    if result.success:
                        sources.add(integration_names[i])
            
            # Cache the result
            self._url_cache[url] = url_result
            url_checks.append(url_result)
        
        return {"url_checks": url_checks, "sources": list(sources)}
    
    async def _analyze_ips(self, ips: List[str]) -> Dict:
        """Analyze IP addresses."""
        ip_checks = []
        sources = set()
        
        abuseipdb = self.integrations.get("abuseipdb")
        if not abuseipdb or not abuseipdb.is_available:
            return {"ip_checks": [], "sources": []}
        
        for ip in ips[:settings.MAX_IPS_TO_ANALYZE]:
            result = await abuseipdb.check_ip(ip)
            ip_checks.append({
                "ip": ip,
                "abuseipdb": result.to_dict() if result.success else {"error": result.error}
            })
            if result.success:
                sources.add("abuseipdb")
        
        return {"ip_checks": ip_checks, "sources": list(sources)}
    
    async def _analyze_domains(self, domains: List[str]) -> Dict:
        """Analyze domains with WHOIS."""
        domain_checks = []
        sources = set()
        
        whois_integration = self.integrations.get("whois")
        if not whois_integration:
            return {"domain_checks": [], "sources": []}
        
        for domain in domains[:settings.MAX_DOMAINS_TO_ANALYZE]:
            result = await whois_integration.check_domain(domain)
            domain_checks.append({
                "domain": domain,
                "whois": result.to_dict() if result.success else {"error": result.error}
            })
            if result.success:
                sources.add("whois")
        
        return {"domain_checks": domain_checks, "sources": list(sources)}
    
    async def _analyze_attachments(self, attachments: List[Attachment]) -> Dict:
        """Analyze attachment hashes."""
        attachment_checks = []
        sources = set()
        
        vt = self.integrations.get("virustotal")
        if not vt or not vt.is_available:
            return {"attachment_checks": [], "sources": []}
        
        for att in attachments:
            if att.sha256_hash:
                result = await vt.check_hash(att.sha256_hash)
                attachment_checks.append({
                    "filename": att.filename,
                    "sha256": att.sha256_hash,
                    "size": att.size,
                    "virustotal": result.to_dict() if result.success else {"error": result.error}
                })
                if result.success:
                    sources.add("virustotal")
        
        return {"attachment_checks": attachment_checks, "sources": list(sources)}
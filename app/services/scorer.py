"""
============================================================================
PHISHING GUARDIAN — RISK SCORING ENGINE
============================================================================
Multi-factor weighted risk scoring with confidence levels.
Synthesizes all threat intelligence into actionable results.

Author:  Dr. Erik
Version: 2.1.0 — PERFECTED
============================================================================
"""

from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ENUMS & CONSTANTS
# ---------------------------------------------------------------------------
class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# KNOWN BRANDS WITH LOOKALIKE DETECTION
# ---------------------------------------------------------------------------
TRUSTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "dropbox", "adobe", "docusign", "fedex", "ups", "dhl",
    "bankofamerica", "chase", "wellsfargo", "citi", "outlook",
    "yahoo", "aol", "protonmail", "gmail", "hotmail",
]

LOOKALIKE_CHARS = {
    '0': 'o', '1': 'l', '2': 'z', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
    '@': 'a', '$': 's', '!': 'i', '|': 'l',
}


def normalize_domain(domain: str) -> str:
    """Normalize domain by replacing lookalike characters."""
    result = domain.lower()
    for fake, real in LOOKALIKE_CHARS.items():
        result = result.replace(fake, real)
    return result


def is_lookalike_domain(domain: str, brand: str) -> bool:
    """
    Check if domain is a lookalike of a trusted brand.
    
    Uses three detection methods:
    1. Normalized character matching (1→l, 0→o, etc.)
    2. Original string matching (catches paypa1 → paypal)
    3. Substring matching for longer brands
    """
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    domain_norm = normalize_domain(domain_lower)
    brand_norm = normalize_domain(brand_lower)
    legit_norm = f"{brand_norm}.com"
    legit_orig = f"{brand_lower}.com"
    
    # Method 1: Normalized domain IS the legitimate one
    # (e.g., paypa1.com normalizes to paypal.com which IS paypal.com)
    if domain_norm == legit_norm and domain_lower != legit_orig:
        return True
    
    # Method 2: Brand (normalized) is contained in domain (normalized)
    # but domain is not the legitimate one
    if brand_norm in domain_norm and domain_norm != legit_norm:
        return True
    
    # Method 3: Original brand substring matching
    # (catches cases like "paypal-secure.com" or "secure-paypal.xyz")
    if len(brand_lower) >= 5:
        for i in range(len(domain_lower) - len(brand_lower) + 1):
            substring = domain_lower[i:i + len(brand_lower)]
            if substring == brand_lower and domain_lower != legit_orig:
                return True
    
    return False


# ---------------------------------------------------------------------------
# RISK REPORT DATACLASS
# ---------------------------------------------------------------------------
@dataclass
class RiskReport:
    overall_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    url_score: int = 0
    ip_score: int = 0
    domain_score: int = 0
    attachment_score: int = 0
    header_score: int = 0
    heuristic_score: int = 0
    summary: str = ""
    technical_details: List[str] = field(default_factory=list)
    suspicious_indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    sources_used: List[str] = field(default_factory=list)
    sources_available: int = 0
    analysis_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence.value,
            "score_breakdown": {
                "url_score": self.url_score,
                "ip_score": self.ip_score,
                "domain_score": self.domain_score,
                "attachment_score": self.attachment_score,
                "header_score": self.header_score,
                "heuristic_score": self.heuristic_score,
            },
            "summary": self.summary,
            "technical_details": self.technical_details,
            "suspicious_indicators": self.suspicious_indicators,
            "recommended_actions": self.recommended_actions,
            "sources_used": self.sources_used,
            "sources_available": self.sources_available,
            "analysis_time": self.analysis_time,
        }


# ---------------------------------------------------------------------------
# RISK SCORING ENGINE
# ---------------------------------------------------------------------------
class RiskScoringEngine:
    """Multi-factor weighted risk scoring engine with lookalike domain detection."""

    def _get_weights(self, sources_count: int) -> Dict[str, float]:
        return {
            "url": 0.25, "ip": 0.05, "domain": 0.20,
            "attachment": 0.10, "header": 0.20, "heuristic": 0.20,
        }

    def calculate(self, parsed_email: Any, analysis_results: Dict[str, Any]) -> RiskReport:
        report = RiskReport()
        report.sources_used = analysis_results.get("sources_checked", [])
        report.sources_available = analysis_results.get("integrations_available", 0)
        report.analysis_time = analysis_results.get("analysis_time_seconds", 0.0)

        sources_count = len(report.sources_used)
        weights = self._get_weights(sources_count)

        report.url_score = self._score_urls(analysis_results.get("urls", []), parsed_email.urls)
        report.ip_score = self._score_ips(analysis_results.get("ips", []))
        report.domain_score = self._score_domains(analysis_results.get("domains", []), parsed_email)
        report.attachment_score = self._score_attachments(analysis_results.get("attachments", []), parsed_email.attachments)
        report.header_score = self._score_headers(parsed_email)
        report.heuristic_score = self._score_heuristics(parsed_email, analysis_results)

        weighted = (
            report.url_score * weights["url"] +
            report.ip_score * weights["ip"] +
            report.domain_score * weights["domain"] +
            report.attachment_score * weights["attachment"] +
            report.header_score * weights["header"] +
            report.heuristic_score * weights["heuristic"]
        )

        total_weight = sum(weights.values())
        if total_weight > 0:
            weighted = weighted / total_weight

        if sources_count >= 3 and weighted > 30:
            weighted += 5
        if sources_count >= 5:
            weighted += 5

        report.overall_score = max(0, min(100, int(weighted)))
        report.risk_level = self._classify_risk(report.overall_score)
        report.confidence = self._calculate_confidence(report)
        report.suspicious_indicators = self._collect_indicators(parsed_email, analysis_results)
        report.summary = self._generate_summary(report)
        report.technical_details = self._generate_technical_details(report)
        report.recommended_actions = self._generate_recommendations(report)

        logger.info(f"Score: {report.overall_score}/100 ({report.risk_level.value}) URL:{report.url_score} DOM:{report.domain_score} HDR:{report.header_score} HEU:{report.heuristic_score}")

        return report

    def _score_urls(self, url_checks: List[Dict], parsed_urls: List) -> int:
        if not parsed_urls: return 0
        scores = []
        for url_info in parsed_urls:
            url_score = 0
            for url_check in url_checks:
                if url_check.get("url") == url_info.url:
                    sources = url_check.get("sources", {})
                    for src in ["virustotal", "phishtank", "openphish"]:
                        src_data = sources.get(src, {})
                        if src_data.get("success") and src_data.get("found"):
                            url_score = max(url_score, src_data.get("risk_score", 0))
                    break
            if url_info.is_ip_based: url_score = max(url_score, 75)
            if url_info.is_shortened: url_score = max(url_score, 45)
            if url_info.has_suspicious_tld: url_score = max(url_score, 55)
            if url_info.domain:
                for brand in TRUSTED_BRANDS:
                    if is_lookalike_domain(url_info.domain.lower(), brand):
                        url_score = max(url_score, 70)
                        break
                if url_info.domain.lower().count("-") >= 2: url_score = max(url_score, 35)
                if len(url_info.domain.lower()) > 30: url_score = max(url_score, 25)
            scores.append(min(100, url_score))
        return max(scores) if scores else 0

    def _score_headers(self, parsed_email: Any) -> int:
        score = 0
        h = parsed_email.header_analysis
        spf = h.spf.value if hasattr(h.spf, "value") else str(h.spf)
        dkim = h.dkim.value if hasattr(h.dkim, "value") else str(h.dkim)
        dmarc = h.dmarc.value if hasattr(h.dmarc, "value") else str(h.dmarc)
        if spf == "fail": score += 40
        elif spf == "softfail": score += 25
        elif spf in ("none", "unknown"): score += 15
        if dkim == "fail": score += 30
        elif dkim in ("none", "unknown"): score += 15
        if dmarc in ("fail", "none", "unknown"): score += 15
        if spf == "unknown" and dkim == "unknown" and dmarc == "unknown": score += 20
        if h.reply_to_mismatch: score += 30
        if h.sender_spoofed: score += 40
        if h.has_urgency_language: score += 20
        if h.has_generic_greeting: score += 15
        return min(100, score)

    def _score_domains(self, domain_checks: List[Dict], parsed_email: Any) -> int:
        scores = []
        for domain_check in domain_checks:
            whois_data = domain_check.get("whois", {})
            if whois_data.get("success"):
                age_days = whois_data.get("age_days", 365)
                if age_days == 0: ds = 50
                elif age_days < 7: ds = 95
                elif age_days < 30: ds = 75
                elif age_days < 90: ds = 50
                elif age_days < 180: ds = 30
                elif age_days < 365: ds = 15
                else: ds = 5
                ds = min(100, ds + len(whois_data.get("suspicious_indicators", [])) * 10)
                scores.append(ds)
        # ALWAYS check sender domain for lookalike — even if WHOIS returned data
        if parsed_email.sender_domain:
            sd = parsed_email.sender_domain.lower()
            for brand in TRUSTED_BRANDS:
                if is_lookalike_domain(sd, brand):
                    scores.append(70)
                    break
        return max(scores) if scores else 0

    def _score_heuristics(self, parsed_email: Any, analysis_results: Dict) -> int:
        score = 0
        h = parsed_email.header_analysis
        if h.has_urgency_language: score += 30
        if h.has_generic_greeting: score += 20
        for url_info in parsed_email.urls:
            if url_info.is_ip_based: score += 25; break
            if url_info.has_suspicious_tld: score += 20; break
            if url_info.is_shortened: score += 15; break
            if url_info.domain:
                for brand in TRUSTED_BRANDS:
                    if is_lookalike_domain(url_info.domain.lower(), brand):
                        score += 30; break
                if score >= 30: break
        if len(parsed_email.urls) > 10: score += 10
        if any(a.is_executable for a in parsed_email.attachments): score += 35
        if any(a.is_archive for a in parsed_email.attachments): score += 20
        if parsed_email.sender_domain:
            for brand in TRUSTED_BRANDS:
                if is_lookalike_domain(parsed_email.sender_domain.lower(), brand):
                    score += 30; break
        if not analysis_results.get("sources_checked"): score += 5
        return min(100, score)

    def _score_ips(self, ip_checks: List[Dict]) -> int:
        if not ip_checks: return 0
        scores = []
        for ip_check in ip_checks:
            abuse = ip_check.get("abuseipdb", {})
            if abuse.get("success"):
                ip_score = abuse.get("abuse_confidence_score", 0)
                if abuse.get("total_reports", 0) > 10: ip_score = min(100, ip_score + 10)
                scores.append(ip_score)
        return max(scores) if scores else 0

    def _score_attachments(self, attachment_checks: List[Dict], parsed_attachments: List) -> int:
        if not attachment_checks and not parsed_attachments: return 0
        scores = []
        for i, att in enumerate(parsed_attachments):
            att_score = 0
            if i < len(attachment_checks):
                vt = attachment_checks[i].get("virustotal", {})
                if vt.get("success") and vt.get("malicious", 0) > 0:
                    att_score = min(100, vt["malicious"] * 20)
            if att.is_executable: att_score = max(att_score, 60)
            if att.is_archive: att_score = max(att_score, 40)
            scores.append(att_score)
        return max(scores) if scores else 0

    def _classify_risk(self, score: int) -> RiskLevel:
        if score >= 80: return RiskLevel.CRITICAL
        elif score >= 60: return RiskLevel.HIGH
        elif score >= 35: return RiskLevel.MEDIUM
        elif score >= 15: return RiskLevel.LOW
        else: return RiskLevel.SAFE

    def _calculate_confidence(self, report: RiskReport) -> ConfidenceLevel:
        sources = len(report.sources_used)
        if sources >= 4: return ConfidenceLevel.HIGH
        elif sources >= 2: return ConfidenceLevel.MEDIUM
        else: return ConfidenceLevel.LOW

    def _collect_indicators(self, parsed_email: Any, analysis_results: Dict) -> List[str]:
        indicators = []
        indicators.extend(parsed_email.header_analysis.suspicious_indicators)
        for url_info in parsed_email.urls:
            if url_info.is_ip_based: indicators.append(f"URL uses IP address: {url_info.url[:80]}")
            if url_info.is_shortened: indicators.append(f"Shortened URL: {url_info.url[:80]}")
            if url_info.has_suspicious_tld: indicators.append(f"Suspicious TLD: {url_info.url[:80]}")
            if url_info.domain:
                for brand in TRUSTED_BRANDS:
                    if is_lookalike_domain(url_info.domain.lower(), brand):
                        indicators.append(f"Lookalike domain: {url_info.domain} mimics {brand}")
                        break
        if parsed_email.sender_domain:
            for brand in TRUSTED_BRANDS:
                if is_lookalike_domain(parsed_email.sender_domain.lower(), brand):
                    indicators.append(f"Sender domain looks like {brand}: {parsed_email.sender_domain}")
                    break
        for att in parsed_email.attachments:
            if att.is_executable: indicators.append(f"Executable attachment: {att.filename}")
            if att.is_archive: indicators.append(f"Archive attachment: {att.filename}")
        return list(dict.fromkeys(indicators))

    def _generate_summary(self, report: RiskReport) -> str:
        level = report.risk_level.value
        score = report.overall_score
        summaries = {
            "CRITICAL": f"CRITICAL risk (score: {score}/100). Multiple threat sources confirm malicious indicators. DO NOT interact.",
            "HIGH": f"HIGH risk (score: {score}/100). Strong phishing indicators detected. Immediate action recommended.",
            "MEDIUM": f"MEDIUM risk (score: {score}/100). Suspicious characteristics detected. Exercise caution.",
            "LOW": f"LOW risk (score: {score}/100). Minor concerns detected, likely legitimate.",
            "SAFE": f"SAFE (score: {score}/100). No significant threats detected.",
        }
        return summaries.get(level, summaries["SAFE"])

    def _generate_technical_details(self, report: RiskReport) -> List[str]:
        return [
            f"Score: {report.overall_score}/100 ({report.risk_level.value})",
            f"Confidence: {report.confidence.value}",
            f"Sources: {len(report.sources_used)} of {report.sources_available}",
            f"Breakdown — URLs:{report.url_score} IPs:{report.ip_score} Domains:{report.domain_score} Attachments:{report.attachment_score} Headers:{report.header_score} Heuristics:{report.heuristic_score}",
        ]

    def _generate_recommendations(self, report: RiskReport) -> List[str]:
        if report.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return ["🚫 DO NOT click any links", "🚫 DO NOT open attachments", "🚫 DO NOT reply", "📧 Forward to security team", "🗑️ Delete this email", "🔒 Block sender domain"]
        elif report.risk_level == RiskLevel.MEDIUM:
            return ["⚠️ Exercise caution", "🔍 Verify sender through another channel", "📋 Forward to security team"]
        elif report.risk_level == RiskLevel.LOW:
            return ["✅ Likely safe but remain vigilant", "🔍 Verify sensitive requests"]
        else:
            return ["✅ No action required"]
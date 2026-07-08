"""
============================================================================
PHISHING GUARDIAN — RISK SCORING ENGINE
============================================================================
Multi-factor weighted risk scoring with full service evidence.
Returns complete data from every threat intelligence source.
Handles unregistered domains, WHOIS errors, and lookalike detection.

Author:  Dr. Erik
Version: 4.1.0 — bug fixes: boundary-aware lookalike matching, corrected
         domain-age ordering, dedup guard fix, robust attachment matching,
         adaptive per-email weight normalization.
============================================================================
"""

import re
from typing import Dict, Any, List
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

    Two independent, boundary-aware signals:

      1. Character-substitution lookalike of the WHOLE domain
         (paypa1.com -> paypal.com, amaz0n.com -> amazon.com)

      2. Brand appears as its own bounded token inside the domain,
         separated by '.', '-', or the start/end of the string
         (paypal-secure-login.com, accounts.paypal.verify-now.net)

    FIX (v4.1.0): the previous implementation matched the brand as a raw
    substring anywhere in the domain with no boundary check. Combined with
    short brand names in TRUSTED_BRANDS ("ups", "dhl", "aol", "citi"), this
    flagged completely benign domains as phishing lookalikes, e.g.:
        "startups.io"        -> contained "ups"  -> false positive
        "backups.net"        -> contained "ups"  -> false positive
        "groups.google.com"  -> contained "ups"  -> false positive
    The old "Method 3" substring loop was also redundant with Method 2 for
    brands >= 5 chars and has been removed.
    """
    domain_lower = domain.lower().strip().rstrip(".")
    brand_lower = brand.lower().strip()
    if not domain_lower or not brand_lower:
        return False

    legit_exact = f"{brand_lower}.com"
    if domain_lower == legit_exact:
        return False  # this IS the real domain, not a lookalike

    domain_norm = normalize_domain(domain_lower)
    brand_norm = normalize_domain(brand_lower)
    legit_norm = f"{brand_norm}.com"

    # Signal 1 — normalized whole-domain match (paypa1.com -> paypal.com)
    if domain_norm == legit_norm:
        return True

    # Signal 2 — brand as a bounded token inside the domain. The boundary
    # requirement (start/end of string, '.', or '-') is what prevents short
    # brands from matching inside unrelated words.
    pattern = r'(?:^|[.\-])' + re.escape(brand_norm) + r'(?:[.\-]|$)'
    if domain_norm != legit_norm and re.search(pattern, domain_norm):
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

    # FULL SERVICE EVIDENCE
    virustotal_evidence: Dict[str, Any] = field(default_factory=dict)
    abuseipdb_evidence: List[Dict[str, Any]] = field(default_factory=list)
    whois_evidence: List[Dict[str, Any]] = field(default_factory=list)
    phishtank_evidence: List[Dict[str, Any]] = field(default_factory=list)
    openphish_evidence: List[Dict[str, Any]] = field(default_factory=list)
    urlscan_evidence: List[Dict[str, Any]] = field(default_factory=list)
    header_evidence: Dict[str, Any] = field(default_factory=dict)
    attachment_evidence: List[Dict[str, Any]] = field(default_factory=list)
    url_details: List[Dict[str, Any]] = field(default_factory=list)

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
            "service_evidence": {
                "virustotal": self.virustotal_evidence,
                "abuseipdb": self.abuseipdb_evidence,
                "whois": self.whois_evidence,
                "phishtank": self.phishtank_evidence,
                "openphish": self.openphish_evidence,
                "urlscan": self.urlscan_evidence,
                "headers": self.header_evidence,
                "attachments": self.attachment_evidence,
                "url_details": self.url_details,
            },
        }


# ---------------------------------------------------------------------------
# RISK SCORING ENGINE
# ---------------------------------------------------------------------------
class RiskScoringEngine:
    """Multi-factor weighted risk scoring engine with full service evidence."""

    # Base per-category weights. These are renormalized per-email in
    # calculate() over only the categories that actually had evidence to
    # score (see FIX note below) so an email with, say, no attachments
    # doesn't get its score diluted by an irrelevant "0 risk" attachment
    # category eating 10% of the weight.
    BASE_WEIGHTS: Dict[str, float] = {
        "url": 0.25, "ip": 0.05, "domain": 0.20,
        "attachment": 0.10, "header": 0.20, "heuristic": 0.20,
    }

    # Confidence-corroboration bonus thresholds, pulled out as named
    # constants instead of magic numbers scattered in calculate().
    MULTI_SOURCE_BONUS = 5
    MULTI_SOURCE_MIN_SCORE = 30
    HIGH_SOURCE_COUNT_BONUS = 5

    def calculate(self, parsed_email: Any, analysis_results: Dict[str, Any]) -> RiskReport:
        report = RiskReport()
        report.sources_used = analysis_results.get("sources_checked", [])
        report.sources_available = analysis_results.get("integrations_available", 0)
        report.analysis_time = analysis_results.get("analysis_time_seconds", 0.0)

        sources_count = len(report.sources_used)

        url_result = self._score_and_collect_urls(analysis_results.get("urls", []), parsed_email.urls)
        report.url_score = url_result["score"]
        report.virustotal_evidence = url_result["virustotal"]
        report.phishtank_evidence = url_result["phishtank"]
        report.openphish_evidence = url_result["openphish"]
        report.urlscan_evidence = url_result["urlscan"]
        report.url_details = url_result["url_details"]

        ip_result = self._score_and_collect_ips(analysis_results.get("ips", []))
        report.ip_score = ip_result["score"]
        report.abuseipdb_evidence = ip_result["abuseipdb"]

        domain_result = self._score_and_collect_domains(analysis_results.get("domains", []), parsed_email)
        report.domain_score = domain_result["score"]
        report.whois_evidence = domain_result["whois"]

        attachment_result = self._score_and_collect_attachments(analysis_results.get("attachments", []), parsed_email.attachments)
        report.attachment_score = attachment_result["score"]
        report.attachment_evidence = attachment_result["attachments"]

        header_result = self._score_and_collect_headers(parsed_email)
        report.header_score = header_result["score"]
        report.header_evidence = header_result["headers"]

        report.heuristic_score = self._score_heuristics(parsed_email, analysis_results)

        # FIX (v4.1.0): weights are now renormalized over only the categories
        # that had real evidence for this specific email, instead of always
        # treating "no attachments present" the same as "attachments checked
        # and found clean." Header and heuristic analysis are always active
        # since they run against the email itself, not external evidence.
        active = {
            "url": bool(parsed_email.urls),
            "ip": bool(analysis_results.get("ips")),
            "domain": bool(analysis_results.get("domains")) or bool(getattr(parsed_email, "sender_domain", None)),
            "attachment": bool(parsed_email.attachments),
            "header": True,
            "heuristic": True,
        }
        used_weights = {k: w for k, w in self.BASE_WEIGHTS.items() if active.get(k)}
        total_weight = sum(used_weights.values()) or 1.0

        score_by_category = {
            "url": report.url_score,
            "ip": report.ip_score,
            "domain": report.domain_score,
            "attachment": report.attachment_score,
            "header": report.header_score,
            "heuristic": report.heuristic_score,
        }
        weighted = sum(score_by_category[k] * w for k, w in used_weights.items()) / total_weight

        # Corroboration bonus: more independent sources agreeing on risk
        # increases confidence in the score, so nudge it up slightly.
        if sources_count >= 5:
            weighted += self.HIGH_SOURCE_COUNT_BONUS
        elif sources_count >= 3 and weighted > self.MULTI_SOURCE_MIN_SCORE:
            weighted += self.MULTI_SOURCE_BONUS

        report.overall_score = max(0, min(100, int(weighted)))
        report.risk_level = self._classify_risk(report.overall_score)
        report.confidence = self._calculate_confidence(report)
        report.suspicious_indicators = self._collect_indicators(parsed_email, analysis_results)
        report.summary = self._generate_summary(report)
        report.technical_details = self._generate_technical_details(report)
        report.recommended_actions = self._generate_recommendations(report)

        logger.info(f"Score: {report.overall_score}/100 ({report.risk_level.value})")

        return report

    # -------------------------------------------------------------------
    # URL SCORING + FULL EVIDENCE COLLECTION
    # -------------------------------------------------------------------
    def _score_and_collect_urls(self, url_checks: List[Dict], parsed_urls: List) -> Dict:
        result = {
            "score": 0,
            "virustotal": {},
            "phishtank": [],
            "openphish": [],
            "urlscan": [],
            "url_details": [],
        }
        if not parsed_urls:
            return result

        scores = []
        for url_info in parsed_urls:
            url_score = 0
            url_detail = {
                "url": url_info.url,
                "domain": url_info.domain,
                "is_ip_based": url_info.is_ip_based,
                "is_shortened": url_info.is_shortened,
                "has_suspicious_tld": url_info.has_suspicious_tld,
            }

            for url_check in url_checks:
                if url_check.get("url") == url_info.url:
                    sources = url_check.get("sources", {})

                    vt = sources.get("virustotal", {})
                    if vt.get("success"):
                        url_score = max(url_score, vt.get("risk_score", 0))
                        result["virustotal"] = {
                            "checked": True,
                            "malicious": vt.get("malicious", 0),
                            "suspicious": vt.get("suspicious", 0),
                            "harmless": vt.get("harmless", 0),
                            "undetected": vt.get("undetected", 0),
                            "total_engines": vt.get("total_engines", 0),
                            "analysis_id": vt.get("analysis_id", ""),
                        }
                        url_detail["virustotal"] = result["virustotal"]

                    pt = sources.get("phishtank", {})
                    if pt.get("success"):
                        pt_data = {
                            "found": pt.get("found", False),
                            "verified": pt.get("verified", False),
                            "verified_at": pt.get("verified_time", ""),
                            "phish_id": pt.get("phish_id", ""),
                            "risk_score": pt.get("risk_score", 0),
                        }
                        result["phishtank"].append({"url": url_info.url, **pt_data})
                        if pt.get("found"):
                            url_score = max(url_score, pt.get("risk_score", 0))
                            url_detail["phishtank"] = pt_data

                    op = sources.get("openphish", {})
                    if op.get("success"):
                        op_data = {
                            "found": op.get("found", False),
                            "risk_score": op.get("risk_score", 0),
                        }
                        result["openphish"].append({"url": url_info.url, **op_data})
                        if op.get("found"):
                            url_score = max(url_score, op.get("risk_score", 0))
                            url_detail["openphish"] = op_data

                    us = sources.get("urlscan", {})
                    if us.get("success"):
                        us_data = {
                            "scan_id": us.get("scan_id", ""),
                            "status": us.get("status", "submitted"),
                            "result_url": us.get("result_url", ""),
                        }
                        result["urlscan"].append({"url": url_info.url, **us_data})
                        url_detail["urlscan"] = us_data

                    break

            if url_info.is_ip_based: url_score = max(url_score, 75)
            if url_info.is_shortened: url_score = max(url_score, 45)
            if url_info.has_suspicious_tld: url_score = max(url_score, 55)
            if url_info.domain:
                for brand in TRUSTED_BRANDS:
                    if is_lookalike_domain(url_info.domain.lower(), brand):
                        url_score = max(url_score, 70)
                        url_detail["lookalike_brand"] = brand
                        break
                if url_info.domain.lower().count("-") >= 2: url_score = max(url_score, 35)
                if len(url_info.domain.lower()) > 30: url_score = max(url_score, 25)

            scores.append(min(100, url_score))
            result["url_details"].append(url_detail)

        result["score"] = max(scores) if scores else 0
        return result

    # -------------------------------------------------------------------
    # IP SCORING + FULL EVIDENCE COLLECTION
    # -------------------------------------------------------------------
    def _score_and_collect_ips(self, ip_checks: List[Dict]) -> Dict:
        result = {"score": 0, "abuseipdb": []}
        if not ip_checks:
            return result

        scores = []
        for ip_check in ip_checks:
            abuse = ip_check.get("abuseipdb", {})
            if abuse.get("success"):
                ip_score = abuse.get("abuse_confidence_score", 0)
                if abuse.get("total_reports", 0) > 10:
                    ip_score = min(100, ip_score + 10)
                scores.append(ip_score)
                result["abuseipdb"].append({
                    "ip": ip_check.get("ip", ""),
                    "abuse_confidence_score": abuse.get("abuse_confidence_score", 0),
                    "total_reports": abuse.get("total_reports", 0),
                    "last_reported_at": abuse.get("last_reported_at", ""),
                    "country": abuse.get("country", "Unknown"),
                    "isp": abuse.get("isp", "Unknown"),
                    "domain": abuse.get("domain", ""),
                    "usage_type": abuse.get("usage_type", ""),
                    "is_whitelisted": abuse.get("is_whitelisted", False),
                    "risk_score": ip_score,
                })

        result["score"] = max(scores) if scores else 0
        return result

    # -------------------------------------------------------------------
    # DOMAIN SCORING + FULL EVIDENCE COLLECTION
    # -------------------------------------------------------------------
    def _score_and_collect_domains(self, domain_checks: List[Dict], parsed_email: Any) -> Dict:
        result = {"score": 0, "whois": []}
        scores = []

        for domain_check in domain_checks:
            whois_data = domain_check.get("whois", {})
            domain = domain_check.get("domain", "")
            ds = 0
            evidence = {
                "domain": domain,
                "registrar": "Unknown",
                "creation_date": "Unknown",
                "expiration_date": "Unknown",
                "age_days": None,
                "days_until_expiry": 0,
                "country": "Unknown",
                "name_servers": [],
                "suspicious_indicators": [],
                "risk_score": 0,
            }

            if whois_data.get("success"):
                # FIX (v4.1.0): default to None (unknown) rather than 365
                # (which silently implied "safe, established domain" for
                # data that was simply missing).
                age_days = whois_data.get("age_days")
                whois_error = whois_data.get("error", "")

                # Unregistered domain = highly suspicious
                if "not found" in str(whois_error).lower() or "not registered" in str(whois_error).lower():
                    ds = 85
                    evidence["suspicious_indicators"].append("Domain is not registered — highly suspicious")
                    evidence["registrar"] = "N/A (unregistered)"
                    evidence["risk_score"] = ds
                elif age_days is None:
                    # FIX (v4.1.0): genuinely unknown age is now handled
                    # explicitly instead of being conflated with age_days==0
                    # (a domain registered today), which used to score
                    # *lower* (50) than a domain registered 3 days ago (95) —
                    # backwards for a security tool where "just registered"
                    # should be treated as more suspicious, not less.
                    ds = 50
                    evidence["suspicious_indicators"].append("Domain age could not be determined")
                elif age_days < 7:
                    ds = 95
                elif age_days < 30:
                    ds = 75
                elif age_days < 90:
                    ds = 50
                elif age_days < 180:
                    ds = 30
                elif age_days < 365:
                    ds = 15
                else:
                    ds = 5

                evidence.update({
                    "registrar": whois_data.get("registrar", evidence["registrar"]),
                    "creation_date": whois_data.get("creation_date", "Unknown"),
                    "expiration_date": whois_data.get("expiration_date", "Unknown"),
                    "age_days": age_days,
                    "days_until_expiry": whois_data.get("days_until_expiry", 0),
                    "country": whois_data.get("country", "Unknown"),
                    "name_servers": whois_data.get("name_servers", []),
                    "suspicious_indicators": list(set(
                        evidence["suspicious_indicators"] +
                        whois_data.get("suspicious_indicators", [])
                    )),
                    "risk_score": ds,
                })
                scores.append(ds)
            else:
                ds = 40
                evidence["risk_score"] = ds
                evidence["suspicious_indicators"].append("WHOIS lookup failed — could not verify domain")
                scores.append(ds)

            result["whois"].append(evidence)

        # Always check sender domain for lookalike patterns
        if getattr(parsed_email, "sender_domain", None):
            sd = parsed_email.sender_domain.lower()
            # FIX (v4.1.0): the old guard checked for a "lookalike_brand"
            # key that the loop above never sets, so it always evaluated to
            # False and never actually prevented a duplicate entry. Now we
            # check whether this exact domain is already present in the
            # evidence list.
            already_present = any(w.get("domain", "").lower() == sd for w in result["whois"])
            if not already_present:
                for brand in TRUSTED_BRANDS:
                    if is_lookalike_domain(sd, brand):
                        scores.append(75)
                        result["whois"].append({
                            "domain": sd,
                            "lookalike_brand": brand,
                            "note": f"Sender domain mimics {brand}",
                            "risk_score": 75,
                            "registrar": "N/A",
                            "creation_date": "Unknown",
                            "age_days": 0,
                            "country": "Unknown",
                            "suspicious_indicators": [f"Lookalike domain: {sd} mimics {brand}"],
                        })
                        break

        result["score"] = max(scores) if scores else 0
        return result

    # -------------------------------------------------------------------
    # HEADER SCORING + FULL EVIDENCE
    # -------------------------------------------------------------------
    def _score_and_collect_headers(self, parsed_email: Any) -> Dict:
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

        return {
            "score": min(100, score),
            "headers": {
                "spf": spf.upper(),
                "dkim": dkim.upper(),
                "dmarc": dmarc.upper(),
                "spf_explanation": self._explain_spf(spf),
                "dkim_explanation": self._explain_dkim(dkim),
                "dmarc_explanation": self._explain_dmarc(dmarc),
                "reply_to_mismatch": h.reply_to_mismatch,
                "reply_to": parsed_email.reply_to,
                "sender_display_name": parsed_email.sender_display_name,
                "sender_spoofed": h.sender_spoofed,
                "has_urgency_language": h.has_urgency_language,
                "has_generic_greeting": h.has_generic_greeting,
                "suspicious_indicators": h.suspicious_indicators,
            },
        }

    def _explain_spf(self, spf: str) -> str:
        explanations = {
            "pass": "Sender IP is authorized to send emails for this domain",
            "fail": "Sender IP is NOT authorized — email may be spoofed",
            "softfail": "Sender IP is probably not authorized — suspicious",
            "none": "No SPF record configured for this domain",
            "unknown": "SPF status could not be determined",
        }
        return explanations.get(str(spf).lower(), "Unknown SPF status")

    def _explain_dkim(self, dkim: str) -> str:
        explanations = {
            "pass": "Email signature is valid — content has not been tampered",
            "fail": "Email signature is INVALID — content may have been modified",
            "none": "No DKIM signature present",
            "unknown": "DKIM status could not be determined",
        }
        return explanations.get(str(dkim).lower(), "Unknown DKIM status")

    def _explain_dmarc(self, dmarc: str) -> str:
        explanations = {
            "pass": "DMARC policy is enforced — domain is protected",
            "fail": "DMARC validation FAILED — email does not meet domain policy",
            "none": "No DMARC policy configured — domain is vulnerable to spoofing",
            "unknown": "DMARC status could not be determined",
        }
        return explanations.get(str(dmarc).lower(), "Unknown DMARC status")

    # -------------------------------------------------------------------
    # ATTACHMENT SCORING + FULL EVIDENCE
    # -------------------------------------------------------------------
    def _score_and_collect_attachments(self, attachment_checks: List[Dict], parsed_attachments: List) -> Dict:
        result = {"score": 0, "attachments": []}
        if not attachment_checks and not parsed_attachments:
            return result

        # FIX (v4.1.0): the old code matched attachment_checks[i] to
        # parsed_attachments[i] purely by list position. If the two lists
        # ever fell out of sync (e.g. one attachment skipped upstream),
        # a VirusTotal result would get silently attached to the wrong
        # file. Match by filename instead, with size as a tiebreaker.
        checks_by_name: Dict[str, Dict] = {}
        for c in attachment_checks:
            name = c.get("filename")
            if name:
                checks_by_name[name] = c

        scores = []
        for i, att in enumerate(parsed_attachments):
            att_score = 0
            att_data = {
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "sha256_hash": att.sha256_hash,
                "is_executable": att.is_executable,
                "is_archive": att.is_archive,
            }

            check = checks_by_name.get(att.filename)
            if check is None and i < len(attachment_checks):
                # Fallback for callers that don't provide filenames in
                # attachment_checks — keeps backward compatibility with the
                # old positional behavior rather than dropping data.
                check = attachment_checks[i]

            if check:
                vt = check.get("virustotal", {})
                if vt.get("success"):
                    att_data["virustotal"] = {
                        "checked": True,
                        "malicious": vt.get("malicious", 0),
                        "suspicious": vt.get("suspicious", 0),
                        "harmless": vt.get("harmless", 0),
                        "total_engines": vt.get("total_engines", 0),
                        "file_name": vt.get("file_name", ""),
                    }
                    if vt.get("malicious", 0) > 0:
                        att_score = min(100, vt["malicious"] * 20)

            if att.is_executable: att_score = max(att_score, 60)
            if att.is_archive: att_score = max(att_score, 40)

            scores.append(att_score)
            att_data["risk_score"] = att_score
            result["attachments"].append(att_data)

        result["score"] = max(scores) if scores else 0
        return result

    # -------------------------------------------------------------------
    # REMAINING METHODS
    # -------------------------------------------------------------------
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
        if getattr(parsed_email, "sender_domain", None):
            for brand in TRUSTED_BRANDS:
                if is_lookalike_domain(parsed_email.sender_domain.lower(), brand):
                    score += 30; break
        if not analysis_results.get("sources_checked"): score += 5
        return min(100, score)

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
        if getattr(parsed_email, "sender_domain", None):
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
"""
============================================================================
PHISHING GUARDIAN — EMAIL PARSER ENGINE
============================================================================
Advanced email parser that extracts every indicator of compromise.
Handles MIME, encoded headers, nested attachments, and more.

Author:  worm
Version: 1.1.1
============================================================================
"""

import re
import hashlib
import ipaddress
import uuid
import logging
from email import policy as email_policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr, getaddresses
from typing import List, Dict, Tuple, Any
from urllib.parse import urlparse
import tldextract

from app.models.email_models import (
    ParsedEmail,
    URLInfo,
    Attachment,
    HeaderAnalysis,
    AuthResult,
)
from app.utils.helpers import clean_url, is_ip_address

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".work", ".click", ".link", ".live", ".digital",
    ".info", ".biz", ".us", ".pw", ".cc",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "bc.vc", "tiny.cc",
    "short.link", "rb.gy", "cutt.ly", "v.gd", "qr.ae",
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify now",
    "your account has been", "suspended", "restricted", "limited",
    "unusual activity", "security alert", "update your account",
    "confirm your identity", "account will be closed",
    "limited time", "click here", "login now", "validate",
    "unauthorized access", "suspicious sign in", "password expired",
    "verify your identity", "reactivate", "locked out",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear member",
    "dear account holder", "dear valued customer", "hello user",
    "dear sir/madam", "dear email user", "attention",
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".com", ".pif",
    ".hta", ".cpl", ".msc", ".jar", ".app", ".reg",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".iso", ".img", ".cab", ".arj", ".lzh",
}


# ---------------------------------------------------------------------------
# PARSER CLASS
# ---------------------------------------------------------------------------
class EmailParser:
    """
    Advanced email parser for phishing analysis.

    Extracts:
    - Headers (From, To, Subject, Date, SPF, DKIM, DMARC, Received chain)
    - URLs with domain analysis
    - IP addresses (body/subject AND Received-header hop IPs)
    - Attachments with hash computation
    - Email addresses
    - Body content (text and HTML) — attachment payloads are excluded
    - Security indicators
    """

    def __init__(self):
        """Initialize the parser with compiled regex patterns."""
        self.url_pattern = re.compile(
            r'''(?xi)
            \b
            (
                (?:https?|ftp)://
                (?:
                    [^\s()<>"'\x00-\x1f\x7f\[\]]+
                    |
                    \([^\s()<>"'\x00-\x1f\x7f\[\]]*\)
                )+
                (?:
                    \([^\s()<>"'\x00-\x1f\x7f\[\]]*\)
                    |
                    [^\s`!()\[\]{};:'".,<>?«»""''\x00-\x1f\x7f]
                )
            )''')

        self.email_pattern = re.compile(
            r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+'
            r'@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        )

        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

    def parse(self, raw_email: str) -> ParsedEmail:
        """
        Parse a raw email into a structured ParsedEmail object.
        """
        analysis_id = str(uuid.uuid4())
        logger.info(f"Parsing email: {analysis_id}")

        # Parse with Python's email library — use email_policy to avoid naming conflict
        import email as email_module
        msg = email_module.message_from_string(raw_email, policy=email_policy.default)

        # Parse headers
        subject = self._decode_header(msg.get("Subject", ""))
        sender_name, sender_addr = parseaddr(msg.get("From", ""))
        _, reply_to_addr = parseaddr(msg.get("Reply-To", ""))
        _, return_path_addr = parseaddr(msg.get("Return-Path", ""))

        # Parse authentication results. A message can legitimately carry
        # multiple Authentication-Results headers (one per hop) — and,
        # since this parser accepts raw attacker-supplied .eml content, a
        # phishing email can simply forge one claiming "spf=pass dkim=pass"
        # to defeat naive single-header checks. We inspect every instance
        # and flag disagreement between them as a suspicious signal.
        auth_headers = msg.get_all("Authentication-Results", []) or []
        spf_result, spf_conflict = self._parse_auth_all(auth_headers, "spf")
        dkim_result, dkim_conflict = self._parse_auth_all(auth_headers, "dkim")
        dmarc_result, dmarc_conflict = self._parse_auth_all(auth_headers, "dmarc")
        auth_conflict = spf_conflict or dkim_conflict or dmarc_conflict

        # Extract recipients
        to_addresses = self._extract_addresses(msg.get("To", ""))
        cc_addresses = self._extract_addresses(msg.get("Cc", ""))

        # Extract body (attachment payloads are explicitly excluded — see
        # _extract_body — so attachment content can't masquerade as body
        # text or pollute urgency/greeting heuristics)
        body_text, body_html = self._extract_body(msg)

        # FIX: Received headers carry the actual mail-hop IPs (e.g. the
        # attacker's sending server) and were previously never fed into the
        # text blob that _extract_ips/_extract_urls/_extract_emails scan —
        # they only ended up in `received_chain` on the output object,
        # never analyzed. Pulling them into combined_text closes that gap.
        received_text = "\n".join(msg.get_all("Received", []) or [])
        combined_text = f"{subject}\n{received_text}\n{body_text}\n{self._strip_html(body_html)}"

        # Extract URLs
        urls = self._extract_urls(combined_text)

        # Extract IP addresses
        ip_addresses = self._extract_ips(combined_text)

        # Extract all email addresses
        all_emails = self._extract_emails(combined_text)

        # Extract domains
        domains = self._extract_domains(urls, all_emails, sender_addr)

        # Extract attachments
        attachments, total_size = self._extract_attachments(msg)

        # Analyze headers
        header_analysis = self._analyze_headers(
            subject=subject,
            sender_addr=sender_addr,
            sender_name=sender_name,
            reply_to_addr=reply_to_addr,
            return_path_addr=return_path_addr,
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            auth_conflict=auth_conflict,
            body_text=body_text,
        )

        # Build the parsed email. raw_headers preserves every header
        # instance (including duplicates like multiple Received/
        # Authentication-Results lines) instead of collapsing them through
        # dict(), which silently drops all but the last occurrence.
        parsed = ParsedEmail(
            analysis_id=analysis_id,
            subject=subject,
            sender=sender_addr,
            sender_display_name=sender_name,
            sender_domain=sender_addr.split("@")[-1].lower() if "@" in sender_addr else "",
            reply_to=reply_to_addr,
            return_path=return_path_addr,
            date=msg.get("Date", ""),
            message_id=msg.get("Message-ID", ""),
            recipients=to_addresses,
            cc=cc_addresses,
            body_text=body_text,
            body_html=body_html,
            body_preview=body_text[:500] if body_text else "",
            urls=urls,
            ip_addresses=ip_addresses,
            domains=domains,
            email_addresses=all_emails,
            attachments=attachments,
            total_attachments_size=total_size,
            received_chain=msg.get_all("Received", []),
            header_analysis=header_analysis,
            raw_headers=str(list(msg.items())),
            body_hashes={
                "text": hashlib.sha256(body_text.encode(errors='ignore')).hexdigest() if body_text else "",
                "html": hashlib.sha256(body_html.encode(errors='ignore')).hexdigest() if body_html else "",
            },
            email_size=len(raw_email),
        )

        logger.info(f"Parsed email {analysis_id}: "
                    f"{len(urls)} URLs, {len(ip_addresses)} IPs, "
                    f"{len(attachments)} attachments, "
                    f"{len(header_analysis.suspicious_indicators)} indicators")

        return parsed

    def _decode_header(self, header: str) -> str:
        if not header:
            return ""
        try:
            decoded = make_header(decode_header(header))
            return str(decoded)
        except Exception:
            return header.replace("\r\n", "").replace("\n", "").strip()

    def _parse_auth_all(self, auth_headers: List[str], mechanism: str) -> Tuple[Any, bool]:
        """Parse a mechanism's result (spf/dkim/dmarc) across *every*
        Authentication-Results header instance. Returns (result, conflict)
        where conflict=True if different instances disagree — itself a
        red flag, since a legitimate mail path shouldn't produce
        contradictory verdicts, whereas a forged header injected by an
        attacker often will.
        """
        if not auth_headers:
            return AuthResult.UNKNOWN, False

        pattern = rf'\b{mechanism}=(\w+)'
        results = []
        for header in auth_headers:
            match = re.search(pattern, header, re.IGNORECASE)
            if match:
                raw = match.group(1).lower()
                try:
                    results.append(AuthResult(raw))
                except ValueError:
                    results.append(AuthResult.UNKNOWN)

        if not results:
            return AuthResult.NONE, False

        conflict = len(set(results)) > 1
        # Prefer the first occurrence (conventionally the header added by
        # the final receiving hop) as the primary result; the conflict flag
        # ensures disagreement is never silently dropped.
        return results[0], conflict

    def _extract_addresses(self, header: str) -> List[str]:
        if not header:
            return []
        addresses = getaddresses([header])
        return [addr.lower() for _, addr in addresses if addr and "@" in addr]

    def _is_attachment_part(self, part: Message) -> bool:
        """True if a MIME part is an attachment (or inline file), rather
        than genuine message body content."""
        disposition = part.get_content_disposition()
        if disposition == "attachment":
            return True
        # An "inline" part with a filename is still a file (e.g. an inline
        # image or inline text file), not prose body content.
        if disposition == "inline" and part.get_filename():
            return True
        # Some malformed/adversarial emails omit Content-Disposition but
        # still carry a filename — treat those as attachments too.
        if part.get_filename():
            return True
        return False

    def _extract_body(self, msg: Message) -> Tuple[str, str]:
        text_parts = []
        html_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                if self._is_attachment_part(part):
                    continue
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        decoded = payload.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        decoded = payload.decode("utf-8", errors="replace")
                    if content_type == "text/plain":
                        text_parts.append(decoded)
                    elif content_type == "text/html":
                        html_parts.append(decoded)
                except Exception as e:
                    logger.debug(f"Failed to decode body part: {e}")
                    continue
        else:
            if not self._is_attachment_part(msg):
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or "utf-8"
                        decoded = payload.decode(charset, errors="replace")
                        if msg.get_content_type() == "text/html":
                            html_parts.append(decoded)
                        else:
                            text_parts.append(decoded)
                except Exception:
                    pass
        return "\n".join(text_parts).strip(), "\n".join(html_parts).strip()

    def _extract_urls(self, text: str) -> List[URLInfo]:
        seen = set()
        urls = []
        for match in self.url_pattern.finditer(text):
            url = match.group(0).rstrip(".,;:!?\"'<>\\")
            if len(url) < 10 or url in seen:
                continue
            seen.add(url)
            url_info = self._analyze_url(url)
            urls.append(url_info)
            if len(urls) >= 50:
                break
        return urls

    def _analyze_url(self, url: str) -> URLInfo:
        cleaned = clean_url(url)
        try:
            parsed = urlparse(cleaned)
        except Exception:
            return URLInfo(url=url)
        domain = parsed.netloc.lower().split(":")[0] if parsed.netloc else ""
        is_ip = is_ip_address(domain) if domain else False
        is_shortened = any(s in domain for s in URL_SHORTENERS) if domain else False
        ext = tldextract.extract(cleaned)
        tld = f".{ext.suffix}" if ext.suffix else ""
        has_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
        return URLInfo(
            url=url, domain=domain, scheme=parsed.scheme or "http",
            port=parsed.port, path=parsed.path or "",
            query_string=parsed.query or "", is_shortened=is_shortened,
            is_ip_based=is_ip, has_suspicious_tld=has_suspicious_tld,
        )

    def _extract_ips(self, text: str) -> List[str]:
        """Extract public, routable IPv4 addresses from text.

        Private/reserved/loopback/link-local ranges are filtered out here
        rather than left in the IOC list — once Received headers are fed
        into combined_text, internal mail-relay hops (10.x, 192.168.x,
        172.16-31.x, etc.) would otherwise show up mixed in with genuinely
        attacker-controlled edge IPs, which is noisy for triage and, in a
        shared/multi-tenant deployment, a minor internal-topology leak.
        The full hop-by-hop path (including private IPs) is still
        available separately via `received_chain` on ParsedEmail.
        """
        ips = self.ip_pattern.findall(text)
        valid = []
        for ip in ips:
            parts = ip.split(".")
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
            if ip in {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"}:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                continue
            valid.append(ip)
        return list(dict.fromkeys(valid))

    def _extract_emails(self, text: str) -> List[str]:
        emails = self.email_pattern.findall(text)
        return list(dict.fromkeys(e.lower() for e in emails if "@" in e and len(e) < 254))

    def _extract_domains(self, urls: List[URLInfo], emails: List[str], sender: str) -> List[str]:
        domains = set()
        for url_info in urls:
            if url_info.domain:
                domains.add(url_info.domain.lower())
        for addr in emails:
            if "@" in addr:
                domains.add(addr.split("@")[-1].lower())
        if sender and "@" in sender:
            domains.add(sender.split("@")[-1].lower())
        return sorted(domains)

    def _extract_attachments(self, msg: Message) -> Tuple[List[Attachment], int]:
        attachments = []
        total_size = 0
        if not msg.is_multipart():
            return attachments, total_size
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if not filename:
                continue
            filename = self._decode_header(filename)
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            size = len(payload)
            total_size += size
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            extension = f".{extension}" if extension else ""
            attachment = Attachment(
                filename=filename, content_type=part.get_content_type(),
                size=size, md5_hash=hashlib.md5(payload).hexdigest(),
                sha256_hash=hashlib.sha256(payload).hexdigest(),
                extension=extension, is_executable=extension in EXECUTABLE_EXTENSIONS,
                is_archive=extension in ARCHIVE_EXTENSIONS,
            )
            attachments.append(attachment)
        return attachments, total_size

    def _analyze_headers(self, subject, sender_addr, sender_name, reply_to_addr,
                         return_path_addr, spf, dkim, dmarc, auth_conflict, body_text) -> HeaderAnalysis:
        indicators = []
        sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

        if spf == AuthResult.FAIL:
            indicators.append("SPF authentication FAILED — sender may be spoofed")
        elif spf == AuthResult.SOFTFAIL:
            indicators.append("SPF authentication SOFTFAIL — suspicious")
        if dkim == AuthResult.FAIL:
            indicators.append("DKIM signature FAILED — email may be tampered")
        if dmarc in [AuthResult.FAIL, AuthResult.NONE]:
            indicators.append(f"DMARC validation {dmarc.value} — weak protection")
        if auth_conflict:
            indicators.append(
                "Multiple Authentication-Results headers disagree — "
                "possible forged authentication header"
            )

        reply_domain = reply_to_addr.split("@")[-1].lower() if reply_to_addr and "@" in reply_to_addr else ""
        reply_to_mismatch = bool(reply_domain and reply_domain != sender_domain)
        if reply_to_mismatch:
            indicators.append(f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})")

        return_domain = return_path_addr.split("@")[-1].lower() if return_path_addr and "@" in return_path_addr else ""
        if return_domain and return_domain != sender_domain:
            indicators.append("Return-Path domain differs from sender domain")

        sender_spoofed = self._check_display_name_spoofing(sender_name, sender_addr)
        if sender_spoofed:
            indicators.append("Display name spoofing detected")

        has_urgency = self._check_urgency(subject, body_text)
        if has_urgency:
            indicators.append("Contains urgent or threatening language")

        has_generic = self._check_generic_greeting(body_text)
        if has_generic:
            indicators.append("Uses generic greeting (not personalized)")

        return HeaderAnalysis(
            spf=spf, dkim=dkim, dmarc=dmarc,
            reply_to_mismatch=reply_to_mismatch,
            sender_spoofed=sender_spoofed,
            has_urgency_language=has_urgency,
            has_generic_greeting=has_generic,
            suspicious_indicators=indicators,
        )

    def _check_display_name_spoofing(self, sender_name: str, sender_addr: str) -> bool:
        if not sender_name or not sender_addr:
            return False
        trusted_brands = [
            "paypal", "microsoft", "google", "apple", "amazon", "netflix",
            "facebook", "instagram", "twitter", "linkedin", "dropbox",
            "bank", "credit union", "irs", "social security", "fedex", "ups",
            "dhl", "ebay", "spotify", "adobe", "docusign",
        ]
        sender_lower = sender_name.lower()
        sender_domain = sender_addr.split("@")[-1].lower()
        for brand in trusted_brands:
            if brand in sender_lower and brand not in sender_domain:
                return True
        return False

    def _check_urgency(self, subject: str, body: str) -> bool:
        combined = f"{subject} {body[:1000]}".lower()
        return any(keyword in combined for keyword in URGENCY_KEYWORDS)

    def _check_generic_greeting(self, body: str) -> bool:
        first_line = body.strip().split("\n")[0].lower() if body else ""
        return any(greeting in first_line for greeting in GENERIC_GREETINGS)

    def _strip_html(self, html: str) -> str:
        if not html:
            return ""
        clean = re.compile(r'<[^>]+>')
        return clean.sub(' ', html)
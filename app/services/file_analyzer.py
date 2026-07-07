"""
============================================================================
PHISHING GUARDIAN — FILE ANALYSIS ENGINE
============================================================================
Analyzes uploaded files for malicious indicators.
Supports PDF, Office documents, ZIP, and executables.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import hashlib
import os
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".msi", ".scr", ".com", ".pif",
    ".hta", ".cpl", ".msc", ".jar", ".app", ".reg", ".sh", ".py",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".iso", ".img", ".cab", ".arj", ".lzh", ".tgz",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".docm", ".xlsm", ".pptm", ".rtf", ".odt", ".ods",
}

SUSPICIOUS_PDF_KEYWORDS = [
    b"/JavaScript", b"/JS ", b"/OpenAction", b"/Launch",
    b"/EmbeddedFile", b"/RichMedia", b"/AA ", b"/AcroForm",
    b"/XFA ", b"/SubmitForm", b"/URI ", b"/GoToE",
]

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


# ---------------------------------------------------------------------------
# FILE ANALYSIS RESULT
# ---------------------------------------------------------------------------
@dataclass
class FileAnalysisResult:
    """Complete file analysis result."""
    filename: str = ""
    file_size: int = 0
    file_extension: str = ""
    sha256_hash: str = ""
    md5_hash: str = ""
    mime_type: str = ""
    file_type: str = "unknown"  # executable, archive, document, other
    
    # VirusTotal results
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_harmless: int = 0
    vt_total: int = 0
    vt_checked: bool = False
    
    # PDF-specific
    pdf_has_javascript: bool = False
    pdf_has_openaction: bool = False
    pdf_has_embedded_files: bool = False
    pdf_suspicious_keywords: list = field(default_factory=list)
    pdf_analyzed: bool = False
    
    # Risk
    risk_score: int = 0
    risk_level: str = "SAFE"
    suspicious_indicators: list = field(default_factory=list)
    recommended_actions: list = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "file_size": self.file_size,
            "file_extension": self.file_extension,
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
            "mime_type": self.mime_type,
            "file_type": self.file_type,
            "virustotal": {
                "checked": self.vt_checked,
                "malicious": self.vt_malicious,
                "suspicious": self.vt_suspicious,
                "harmless": self.vt_harmless,
                "total": self.vt_total,
            },
            "pdf_analysis": {
                "analyzed": self.pdf_analyzed,
                "has_javascript": self.pdf_has_javascript,
                "has_openaction": self.pdf_has_openaction,
                "has_embedded_files": self.pdf_has_embedded_files,
                "suspicious_keywords": self.pdf_suspicious_keywords,
            },
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "suspicious_indicators": self.suspicious_indicators,
            "recommended_actions": self.recommended_actions,
        }


# ---------------------------------------------------------------------------
# FILE ANALYZER
# ---------------------------------------------------------------------------
class FileAnalyzer:
    """Analyzes files for malicious indicators."""
    
    def analyze(self, filename: str, file_data: bytes) -> FileAnalysisResult:
        """Perform complete file analysis."""
        result = FileAnalysisResult()
        
        # Basic file info
        result.filename = filename or "unknown"
        result.file_size = len(file_data)
        result.file_extension = self._get_extension(filename).lower()
        result.file_type = self._classify_file_type(result.file_extension)
        
        # Hash computation
        result.sha256_hash = hashlib.sha256(file_data).hexdigest()
        result.md5_hash = hashlib.md5(file_data).hexdigest()
        
        # MIME type detection
        result.mime_type = self._detect_mime_type(file_data)
        
        # File type specific analysis
        if result.file_extension == ".pdf":
            self._analyze_pdf(file_data, result)
        
        # Heuristic scoring (before API results)
        self._heuristic_scoring(result)
        
        logger.info(
            f"File analyzed: {result.filename} "
            f"Type: {result.file_type} "
            f"SHA256: {result.sha256_hash[:16]} "
            f"Heuristic Score: {result.risk_score}"
        )
        
        return result
    
    def _get_extension(self, filename: str) -> str:
        """Extract file extension."""
        if not filename or "." not in filename:
            return ""
        return filename.rsplit(".", 1)[-1] if "." in filename else ""
    
    def _classify_file_type(self, extension: str) -> str:
        """Classify file by extension."""
        if extension in EXECUTABLE_EXTENSIONS:
            return "executable"
        elif extension in ARCHIVE_EXTENSIONS:
            return "archive"
        elif extension in DOCUMENT_EXTENSIONS:
            return "document"
        else:
            return "other"
    
    def _detect_mime_type(self, data: bytes) -> str:
        """Detect MIME type from magic bytes."""
        if data.startswith(b"%PDF"):
            return "application/pdf"
        elif data.startswith(b"PK\x03\x04"):
            return "application/zip"
        elif data.startswith(b"MZ"):
            return "application/x-msdownload"
        elif data.startswith(b"\xD0\xCF\x11\xE0"):
            return "application/msword"
        elif data.startswith(b"GIF89a") or data.startswith(b"GIF87a"):
            return "image/gif"
        elif data.startswith(b"\x89PNG"):
            return "image/png"
        elif data.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        return "application/octet-stream"
    
    def _analyze_pdf(self, data: bytes, result: FileAnalysisResult):
        """Analyze PDF file for suspicious content."""
        result.pdf_analyzed = True
        
        try:
            # Search for suspicious keywords
            for keyword in SUSPICIOUS_PDF_KEYWORDS:
                if keyword in data:
                    result.pdf_suspicious_keywords.append(keyword.decode("utf-8", errors="ignore"))
            
            # Specific checks
            if b"/JavaScript" in data or b"/JS " in data:
                result.pdf_has_javascript = True
            if b"/OpenAction" in data:
                result.pdf_has_openaction = True
            if b"/EmbeddedFile" in data:
                result.pdf_has_embedded_files = True
            
            logger.info(
                f"PDF analysis: JS={result.pdf_has_javascript} "
                f"OpenAction={result.pdf_has_openaction} "
                f"Embedded={result.pdf_has_embedded_files} "
                f"Keywords={len(result.pdf_suspicious_keywords)}"
            )
        except Exception as e:
            logger.error(f"PDF analysis failed: {e}")
    
    def _heuristic_scoring(self, result: FileAnalysisResult):
        """Calculate heuristic risk score before API checks."""
        score = 0
        
        # File type risks
        if result.file_type == "executable":
            score += 50
            result.suspicious_indicators.append("Executable file detected — high risk")
        elif result.file_type == "archive":
            score += 30
            result.suspicious_indicators.append("Archive file — may contain malicious content")
        
        # PDF-specific risks
        if result.pdf_has_javascript:
            score += 40
            result.suspicious_indicators.append("PDF contains JavaScript — common malware vector")
        if result.pdf_has_openaction:
            score += 25
            result.suspicious_indicators.append("PDF has automatic actions configured")
        if result.pdf_has_embedded_files:
            score += 35
            result.suspicious_indicators.append("PDF contains embedded files")
        if len(result.pdf_suspicious_keywords) >= 3:
            score += 30
            result.suspicious_indicators.append(
                f"PDF contains {len(result.pdf_suspicious_keywords)} suspicious elements"
            )
        
        result.risk_score = min(100, score)
        result.risk_level = self._classify_risk(result.risk_score)
        result.recommended_actions = self._get_recommendations(result)
    
    def apply_vt_results(self, result: FileAnalysisResult, vt_data: Dict[str, Any]):
        """Apply VirusTotal results to the analysis."""
        if not vt_data.get("success"):
            return
        
        result.vt_checked = True
        result.vt_malicious = vt_data.get("malicious", 0)
        result.vt_suspicious = vt_data.get("suspicious", 0)
        result.vt_harmless = vt_data.get("harmless", 0)
        result.vt_total = vt_data.get("total_engines", 0)
        
        # Adjust risk score based on VT results
        if result.vt_malicious > 0:
            result.risk_score = max(result.risk_score, 90)
            result.suspicious_indicators.append(
                f"VirusTotal: {result.vt_malicious}/{result.vt_total} engines detected as malicious"
            )
        elif result.vt_suspicious > 0:
            result.risk_score = max(result.risk_score, 60)
            result.suspicious_indicators.append(
                f"VirusTotal: {result.vt_suspicious} engines flagged as suspicious"
            )
        
        result.risk_level = self._classify_risk(result.risk_score)
        result.recommended_actions = self._get_recommendations(result)
    
    def _classify_risk(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        elif score >= 60: return "HIGH"
        elif score >= 35: return "MEDIUM"
        elif score >= 15: return "LOW"
        else: return "SAFE"
    
    def _get_recommendations(self, result: FileAnalysisResult) -> list:
        if result.risk_level in ("CRITICAL", "HIGH"):
            return [
                "🚫 DO NOT open this file",
                "🚫 DO NOT execute or enable macros",
                "📧 Forward to security team immediately",
                "🗑️ Delete this file from all locations",
                "🔒 Block sender and scan all systems",
            ]
        elif result.risk_level == "MEDIUM":
            return [
                "⚠️ Exercise caution — scan with updated antivirus",
                "🔍 Submit to sandbox for further analysis",
                "📋 Report to security team",
            ]
        elif result.risk_level == "LOW":
            return [
                "✅ Likely safe but scan before opening",
                "🔍 Verify source before executing",
            ]
        else:
            return ["✅ No threats detected", "📋 Standard security practices apply"]
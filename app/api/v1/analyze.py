"""
============================================================================
PHISHING GUARDIAN — UNIFIED ANALYSIS ENDPOINT
============================================================================
Handles email text, .eml files, PDFs, Office documents, ZIP, and executables.
Routes to appropriate analyzer and returns unified risk assessment.

Author:  Dr. Erik
Version: 2.0.0 — Email + File Analysis
============================================================================
"""

import time
import logging
import asyncio
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, status, Depends, Form, File, UploadFile

from app.api.deps import check_rate_limit, get_analysis_services
from app.services.database_service import DatabaseService
from app.services.file_analyzer import FileAnalyzer, MAX_FILE_SIZE

logger = logging.getLogger(__name__)

router = APIRouter()

# Allowed file types for analysis
ALLOWED_EXTENSIONS = {
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".docm", ".xlsm", ".pptm", ".rtf", ".odt", ".ods",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso",
    # Executables
    ".exe", ".dll", ".msi", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    # Email
    ".eml", ".msg",
}


@router.post("/analyze")
async def analyze(
    request: Request,
    raw_email: Optional[str] = Form(None, description="Raw email text with headers"),
    uploaded_file: Optional[UploadFile] = File(None, description="File to analyze (.eml, .pdf, .docx, .zip, etc.)"),
    _rate_limit: dict = Depends(check_rate_limit),
    services: dict = Depends(get_analysis_services),
):
    """
    Unified analysis endpoint — accepts emails OR files.
    
    **Email Analysis:** Paste raw email text or upload .eml file
    **File Analysis:** Upload PDF, Office documents, ZIP, or executables
    
    Returns:
    - Overall risk score (0-100)
    - Risk level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
    - Detailed indicators from multiple threat intelligence sources
    - Actionable recommendations
    """
    start_time = time.time()
    
    # -------------------------------------------------------------------
    # DETERMINE WHAT WAS SUBMITTED
    # -------------------------------------------------------------------
    has_email_text = raw_email and raw_email.strip()
    has_file = uploaded_file and uploaded_file.filename
    
    if not has_email_text and not has_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "No content provided",
                "message": "Paste a raw email or upload a file to analyze"
            }
        )
    
    # -------------------------------------------------------------------
    # FILE ANALYSIS PATH
    # -------------------------------------------------------------------
    if has_file:
        return await _analyze_file(uploaded_file, services, start_time)
    
    # -------------------------------------------------------------------
    # EMAIL ANALYSIS PATH
    # -------------------------------------------------------------------
    if has_email_text:
        return await _analyze_email(raw_email, services, start_time)


# ===========================================================================
# EMAIL ANALYSIS
# ===========================================================================
async def _analyze_email(raw_email: str, services: dict, start_time: float):
    """Analyze raw email text."""
    logger.info("Starting email analysis...")
    
    # Parse email
    try:
        parser = services["parser"]
        parsed_email = parser.parse(raw_email)
    except Exception as e:
        logger.error(f"Email parsing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Failed to parse email", "message": str(e)}
        )
    
    # Run threat intelligence analysis
    try:
        analyzer = services["analyzer"]
        analysis_results = await analyzer.analyze(parsed_email)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        analysis_results = {
            "urls": [], "ips": [], "domains": [], "attachments": [],
            "sources_checked": [], "integrations_available": 0,
            "analysis_time_seconds": 0.0,
        }
    
    # Calculate risk score
    scorer = services["scorer"]
    risk_report = scorer.calculate(parsed_email, analysis_results)
    
    total_time = round(time.time() - start_time, 2)
    
    # Build response
    response = {
        "analysis_type": "email",
        "analysis_id": parsed_email.analysis_id,
        "timestamp": parsed_email.parsed_at,
        "analysis_time_seconds": total_time,
        "email_summary": {
            "subject": parsed_email.subject,
            "sender": parsed_email.sender,
            "sender_display_name": parsed_email.sender_display_name,
            "sender_domain": parsed_email.sender_domain,
            "date": parsed_email.date,
            "recipients_count": len(parsed_email.recipients),
            "urls_found": len(parsed_email.urls),
            "attachments_found": len(parsed_email.attachments),
            "ips_found": len(parsed_email.ip_addresses),
            "domains_found": len(parsed_email.domains),
            "body_preview": (parsed_email.body_preview or "")[:500],
        },
        "risk_assessment": risk_report.to_dict(),
        "header_analysis": {
            "spf": _safe_enum(parsed_email.header_analysis.spf),
            "dkim": _safe_enum(parsed_email.header_analysis.dkim),
            "dmarc": _safe_enum(parsed_email.header_analysis.dmarc),
            "reply_to_mismatch": parsed_email.header_analysis.reply_to_mismatch,
            "sender_spoofed": parsed_email.header_analysis.sender_spoofed,
            "has_urgency_language": parsed_email.header_analysis.has_urgency_language,
            "has_generic_greeting": parsed_email.header_analysis.has_generic_greeting,
        },
        "sources_checked": analysis_results.get("sources_checked", []),
        "sources_available": analysis_results.get("integrations_available", 0),
        "urls": [
            {
                "url": u.url, "domain": u.domain,
                "is_ip_based": u.is_ip_based, "is_shortened": u.is_shortened,
                "has_suspicious_tld": u.has_suspicious_tld, "risk_score": u.risk_score,
            }
            for u in parsed_email.urls[:10]
        ],
        "attachments": [
            {
                "filename": a.filename, "content_type": a.content_type,
                "size": a.size, "sha256": a.sha256_hash,
                "is_executable": a.is_executable, "is_archive": a.is_archive,
            }
            for a in parsed_email.attachments
        ],
    }
    
    # Save to database asynchronously
    _save_to_db(response, raw_email)
    
    logger.info(f"Email analysis complete: Score={risk_report.overall_score}/100 Time={total_time}s")
    return response


# ===========================================================================
# FILE ANALYSIS
# ===========================================================================
async def _analyze_file(uploaded_file: UploadFile, services: dict, start_time: float):
    """Analyze uploaded file."""
    logger.info(f"Starting file analysis: {uploaded_file.filename}")
    
    # Validate file extension
    filename = uploaded_file.filename or "unknown"
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    extension = f".{extension}" if extension else ""
    
    if extension and extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Unsupported file type",
                "message": f"File type '{extension}' is not supported. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            }
        )
    
    # Validate file size
    file_data = await uploaded_file.read()
    if len(file_data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "File too large",
                "message": f"Maximum file size is {MAX_FILE_SIZE // (1024*1024)}MB"
            }
        )
    
    # If it's an .eml file, treat as email
    if extension == ".eml":
        try:
            raw_email = file_data.decode("utf-8", errors="ignore")
            return await _analyze_email(raw_email, services, start_time)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "Failed to read .eml file", "message": str(e)}
            )
    
    # Analyze the file
    file_analyzer = FileAnalyzer()
    result = file_analyzer.analyze(filename, file_data)
    
    # Check VirusTotal if available
    try:
        analyzer = services["analyzer"]
        vt_integration = analyzer.integrations.get("virustotal")
        if vt_integration and vt_integration.is_available:
            vt_result = await vt_integration.check_hash(result.sha256_hash)
            if vt_result.success:
                file_analyzer.apply_vt_results(result, vt_result.data)
                logger.info(f"VirusTotal check complete: {result.vt_malicious}/{result.vt_total}")
    except Exception as e:
        logger.warning(f"VirusTotal check failed: {e}")
    
    total_time = round(time.time() - start_time, 2)
    
    # Build response
    import uuid
    response = {
        "analysis_type": "file",
        "analysis_id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "analysis_time_seconds": total_time,
        "file_analysis": result.to_dict(),
        "sources_checked": ["virustotal"] if result.vt_checked else [],
        "sources_available": 1,
    }
    
    logger.info(f"File analysis complete: {result.risk_level} Score={result.risk_score}/100 Time={total_time}s")
    return response


# ===========================================================================
# HELPERS
# ===========================================================================
def _safe_enum(value) -> str:
    """Safely extract string value from enum or return raw string."""
    if hasattr(value, "value"):
        return value.value
    return str(value)


def _save_to_db(response: dict, raw_content: str):
    """Fire-and-forget database save."""
    try:
        save_data = response.copy()
        save_data["_raw_email"] = raw_content
        asyncio.create_task(DatabaseService.save_analysis(save_data))
    except Exception as e:
        logger.error(f"Failed to queue database save: {e}")
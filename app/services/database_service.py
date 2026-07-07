"""
============================================================================
PHISHING GUARDIAN — DATABASE SERVICE
============================================================================
Service layer for all database operations.
Abstracts SQLAlchemy queries behind clean async functions.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

import json
import hashlib
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import (
    AnalysisRecord, URLRecord, AttachmentRecord, async_session
)

logger = logging.getLogger(__name__)


class DatabaseService:
    """Service for persisting and retrieving analysis records."""
    
    # -----------------------------------------------------------------------
    # SAVE
    # -----------------------------------------------------------------------
    @staticmethod
    async def save_analysis(analysis_data: Dict[str, Any]) -> Optional[AnalysisRecord]:
        """Save a complete analysis to the database."""
        try:
            async with async_session() as session:
                risk = analysis_data.get("risk_assessment", {})
                email_summary = analysis_data.get("email_summary", {})
                header_analysis = analysis_data.get("header_analysis", {})
                breakdown = risk.get("score_breakdown", {})
                
                # Hash the raw email for deduplication
                raw_email = analysis_data.get("_raw_email", "")
                email_hash = hashlib.sha256(raw_email.encode()).hexdigest() if raw_email else ""
                
                record = AnalysisRecord(
                    analysis_id=analysis_data.get("analysis_id", ""),
                    subject=email_summary.get("subject", ""),
                    sender=email_summary.get("sender", ""),
                    sender_domain=email_summary.get("sender_domain", ""),
                    sender_display_name=email_summary.get("sender_display_name", ""),
                    recipients_count=email_summary.get("recipients_count", 0),
                    urls_found=email_summary.get("urls_found", 0),
                    attachments_found=email_summary.get("attachments_found", 0),
                    ips_found=email_summary.get("ips_found", 0),
                    domains_found=email_summary.get("domains_found", 0),
                    body_preview=email_summary.get("body_preview", "")[:500],
                    overall_score=risk.get("overall_score", 0),
                    risk_level=risk.get("risk_level", "SAFE"),
                    confidence=risk.get("confidence", "LOW"),
                    url_score=breakdown.get("url_score", 0),
                    header_score=breakdown.get("header_score", 0),
                    domain_score=breakdown.get("domain_score", 0),
                    attachment_score=breakdown.get("attachment_score", 0),
                    heuristic_score=breakdown.get("heuristic_score", 0),
                    ip_score=breakdown.get("ip_score", 0),
                    spf_result=header_analysis.get("spf", "unknown"),
                    dkim_result=header_analysis.get("dkim", "unknown"),
                    dmarc_result=header_analysis.get("dmarc", "unknown"),
                    reply_to_mismatch=header_analysis.get("reply_to_mismatch", False),
                    sender_spoofed=header_analysis.get("sender_spoofed", False),
                    has_urgency_language=header_analysis.get("has_urgency_language", False),
                    has_generic_greeting=header_analysis.get("has_generic_greeting", False),
                    summary=risk.get("summary", ""),
                    suspicious_indicators=json.dumps(risk.get("suspicious_indicators", [])),
                    recommended_actions=json.dumps(risk.get("recommended_actions", [])),
                    sources_checked=json.dumps(analysis_data.get("sources_checked", [])),
                    sources_available=analysis_data.get("sources_available", 0),
                    analysis_time_seconds=analysis_data.get("analysis_time_seconds", 0.0),
                    raw_email_hash=email_hash,
                    full_response_json=json.dumps(analysis_data, default=str),
                )
                
                session.add(record)
                await session.flush()  # Get the ID
                
                # Save URLs
                for url_data in analysis_data.get("urls", []):
                    url_record = URLRecord(
                        analysis_id_fk=record.id,
                        url=url_data.get("url", ""),
                        domain=url_data.get("domain", ""),
                        is_ip_based=url_data.get("is_ip_based", False),
                        is_shortened=url_data.get("is_shortened", False),
                        has_suspicious_tld=url_data.get("has_suspicious_tld", False),
                        risk_score=url_data.get("risk_score", 0),
                    )
                    session.add(url_record)
                
                # Save attachments
                for att_data in analysis_data.get("attachments", []):
                    att_record = AttachmentRecord(
                        analysis_id_fk=record.id,
                        filename=att_data.get("filename", ""),
                        content_type=att_data.get("content_type", ""),
                        size=att_data.get("size", 0),
                        sha256_hash=att_data.get("sha256", ""),
                        is_executable=att_data.get("is_executable", False),
                        is_archive=att_data.get("is_archive", False),
                    )
                    session.add(att_record)
                
                await session.commit()
                logger.info(f"Saved analysis: {record.analysis_id}")
                return record
                
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return None
    
    # -----------------------------------------------------------------------
    # RETRIEVE
    # -----------------------------------------------------------------------
    @staticmethod
    async def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single analysis by its ID."""
        try:
            async with async_session() as session:
                stmt = select(AnalysisRecord).where(
                    AnalysisRecord.analysis_id == analysis_id
                )
                result = await session.execute(stmt)
                record = result.scalar_one_or_none()
                
                if record:
                    return DatabaseService._record_to_dict(record)
                return None
        except Exception as e:
            logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
            return None
    
    @staticmethod
    async def get_history(
        limit: int = 50,
        offset: int = 0,
        risk_level: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve paginated analysis history with optional filters."""
        try:
            async with async_session() as session:
                # Base query
                stmt = select(AnalysisRecord)
                
                # Filters
                conditions = []
                if risk_level:
                    conditions.append(AnalysisRecord.risk_level == risk_level.upper())
                if search:
                    search_term = f"%{search}%"
                    conditions.append(
                        AnalysisRecord.subject.ilike(search_term) |
                        AnalysisRecord.sender.ilike(search_term) |
                        AnalysisRecord.sender_domain.ilike(search_term)
                    )
                if start_date:
                    conditions.append(AnalysisRecord.created_at >= datetime.fromisoformat(start_date))
                if end_date:
                    conditions.append(AnalysisRecord.created_at <= datetime.fromisoformat(end_date))
                
                if conditions:
                    stmt = stmt.where(and_(*conditions))
                
                # Get total count
                count_stmt = select(func.count()).select_from(stmt.subquery())
                count_result = await session.execute(count_stmt)
                total = count_result.scalar() or 0
                
                # Get paginated results
                stmt = stmt.order_by(desc(AnalysisRecord.created_at))
                stmt = stmt.offset(offset).limit(limit)
                result = await session.execute(stmt)
                records = result.scalars().all()
                
                return {
                    "analyses": [DatabaseService._record_to_summary(r) for r in records],
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                }
        except Exception as e:
            logger.error(f"Failed to retrieve history: {e}")
            return {"analyses": [], "total": 0, "limit": limit, "offset": offset}
    
    @staticmethod
    async def get_statistics() -> Dict[str, Any]:
        """Get aggregate statistics from the database."""
        try:
            async with async_session() as session:
                # Total analyses
                total_stmt = select(func.count(AnalysisRecord.id))
                total_result = await session.execute(total_stmt)
                total = total_result.scalar() or 0
                
                # Count by risk level
                risk_stmt = select(
                    AnalysisRecord.risk_level,
                    func.count(AnalysisRecord.id)
                ).group_by(AnalysisRecord.risk_level)
                risk_result = await session.execute(risk_stmt)
                risk_counts = {row[0]: row[1] for row in risk_result}
                
                # Average score
                avg_stmt = select(func.avg(AnalysisRecord.overall_score))
                avg_result = await session.execute(avg_stmt)
                avg_score = round(avg_result.scalar() or 0, 1)
                
                # Today's analyses
                today_stmt = select(func.count(AnalysisRecord.id)).where(
                    AnalysisRecord.created_at >= datetime.utcnow().replace(
                        hour=0, minute=0, second=0, microsecond=0
                    )
                )
                today_result = await session.execute(today_stmt)
                today_count = today_result.scalar() or 0
                
                return {
                    "total_analyses": total,
                    "average_score": avg_score,
                    "today_count": today_count,
                    "by_risk_level": risk_counts,
                }
        except Exception as e:
            logger.error(f"Failed to retrieve statistics: {e}")
            return {
                "total_analyses": 0,
                "average_score": 0,
                "today_count": 0,
                "by_risk_level": {},
            }
    
    # -----------------------------------------------------------------------
    # DELETE
    # -----------------------------------------------------------------------
    @staticmethod
    async def delete_analysis(analysis_id: str) -> bool:
        """Delete an analysis by its ID."""
        try:
            async with async_session() as session:
                stmt = select(AnalysisRecord).where(
                    AnalysisRecord.analysis_id == analysis_id
                )
                result = await session.execute(stmt)
                record = result.scalar_one_or_none()
                
                if record:
                    await session.delete(record)
                    await session.commit()
                    logger.info(f"Deleted analysis: {analysis_id}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to delete analysis {analysis_id}: {e}")
            return False
    
    # -----------------------------------------------------------------------
    # HELPERS
    # -----------------------------------------------------------------------
    @staticmethod
    def _record_to_dict(record: AnalysisRecord) -> Dict[str, Any]:
        """Convert a database record to a full dictionary."""
        return {
            "analysis_id": record.analysis_id,
            "created_at": record.created_at.isoformat() if record.created_at else "",
            "email_summary": {
                "subject": record.subject,
                "sender": record.sender,
                "sender_domain": record.sender_domain,
                "sender_display_name": record.sender_display_name,
                "recipients_count": record.recipients_count,
                "urls_found": record.urls_found,
                "attachments_found": record.attachments_found,
                "ips_found": record.ips_found,
                "domains_found": record.domains_found,
                "body_preview": record.body_preview,
            },
            "risk_assessment": {
                "overall_score": record.overall_score,
                "risk_level": record.risk_level,
                "confidence": record.confidence,
                "summary": record.summary,
                "score_breakdown": {
                    "url_score": record.url_score,
                    "header_score": record.header_score,
                    "domain_score": record.domain_score,
                    "attachment_score": record.attachment_score,
                    "heuristic_score": record.heuristic_score,
                    "ip_score": record.ip_score,
                },
                "suspicious_indicators": json.loads(record.suspicious_indicators or "[]"),
                "recommended_actions": json.loads(record.recommended_actions or "[]"),
            },
            "header_analysis": {
                "spf": record.spf_result,
                "dkim": record.dkim_result,
                "dmarc": record.dmarc_result,
                "reply_to_mismatch": record.reply_to_mismatch,
                "sender_spoofed": record.sender_spoofed,
                "has_urgency_language": record.has_urgency_language,
                "has_generic_greeting": record.has_generic_greeting,
            },
            "sources_checked": json.loads(record.sources_checked or "[]"),
            "sources_available": record.sources_available,
            "analysis_time_seconds": record.analysis_time_seconds,
        }
    
    @staticmethod
    def _record_to_summary(record: AnalysisRecord) -> Dict[str, Any]:
        """Convert a database record to a summary (for list views)."""
        return {
            "id": record.id,
            "analysis_id": record.analysis_id,
            "subject": record.subject or "No Subject",
            "sender": record.sender or "Unknown",
            "sender_domain": record.sender_domain or "",
            "overall_score": record.overall_score,
            "risk_level": record.risk_level,
            "urls_found": record.urls_found,
            "attachments_found": record.attachments_found,
            "created_at": record.created_at.isoformat() if record.created_at else "",
        }
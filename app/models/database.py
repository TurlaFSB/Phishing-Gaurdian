"""
============================================================================
PHISHING GUARDIAN — DATABASE MODELS
============================================================================
SQLAlchemy async ORM models with SQLite backend.
Zero configuration required — works out of the box.

Author:  Dr. Erik
Version: 1.0.0
============================================================================
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, 
    Boolean, ForeignKey, JSON, Index, create_engine, select
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from app.core.config import settings


# ---------------------------------------------------------------------------
# BASE
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# ---------------------------------------------------------------------------
# ENGINE & SESSION
# ---------------------------------------------------------------------------
# SQLite with async support via aiosqlite
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

# Session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------------
class AnalysisRecord(Base):
    """Stores each email analysis for history and audit purposes."""
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    
    # Email metadata
    subject: Mapped[Optional[str]] = mapped_column(String(500), default="")
    sender: Mapped[Optional[str]] = mapped_column(String(320), default="")
    sender_domain: Mapped[Optional[str]] = mapped_column(String(255), default="")
    sender_display_name: Mapped[Optional[str]] = mapped_column(String(255), default="")
    recipients_count: Mapped[int] = mapped_column(Integer, default=0)
    urls_found: Mapped[int] = mapped_column(Integer, default=0)
    attachments_found: Mapped[int] = mapped_column(Integer, default=0)
    ips_found: Mapped[int] = mapped_column(Integer, default=0)
    domains_found: Mapped[int] = mapped_column(Integer, default=0)
    body_preview: Mapped[Optional[str]] = mapped_column(Text, default="")
    
    # Risk assessment
    overall_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="SAFE", index=True)
    confidence: Mapped[str] = mapped_column(String(20), default="LOW")
    
    # Score breakdown
    url_score: Mapped[int] = mapped_column(Integer, default=0)
    header_score: Mapped[int] = mapped_column(Integer, default=0)
    domain_score: Mapped[int] = mapped_column(Integer, default=0)
    attachment_score: Mapped[int] = mapped_column(Integer, default=0)
    heuristic_score: Mapped[int] = mapped_column(Integer, default=0)
    ip_score: Mapped[int] = mapped_column(Integer, default=0)
    
    # Header analysis
    spf_result: Mapped[str] = mapped_column(String(20), default="unknown")
    dkim_result: Mapped[str] = mapped_column(String(20), default="unknown")
    dmarc_result: Mapped[str] = mapped_column(String(20), default="unknown")
    reply_to_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    sender_spoofed: Mapped[bool] = mapped_column(Boolean, default=False)
    has_urgency_language: Mapped[bool] = mapped_column(Boolean, default=False)
    has_generic_greeting: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Full data (JSON)
    summary: Mapped[Optional[str]] = mapped_column(Text, default="")
    suspicious_indicators: Mapped[Optional[str]] = mapped_column(Text, default="[]")
    recommended_actions: Mapped[Optional[str]] = mapped_column(Text, default="[]")
    sources_checked: Mapped[Optional[str]] = mapped_column(Text, default="[]")
    sources_available: Mapped[int] = mapped_column(Integer, default=0)
    analysis_time_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Full raw data
    raw_email_hash: Mapped[Optional[str]] = mapped_column(String(64), default="")
    full_response_json: Mapped[Optional[str]] = mapped_column(Text, default="{}")
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    
    # Relationships
    urls: Mapped[List["URLRecord"]] = relationship(
        "URLRecord", back_populates="analysis", cascade="all, delete-orphan"
    )
    attachments: Mapped[List["AttachmentRecord"]] = relationship(
        "AttachmentRecord", back_populates="analysis", cascade="all, delete-orphan"
    )
    
    # Composite index for common queries
    __table_args__ = (
        Index("idx_risk_score_date", "risk_level", "created_at"),
        Index("idx_sender_domain", "sender_domain"),
    )
    
    def __repr__(self):
        return f"<Analysis {self.analysis_id}: {self.risk_level} ({self.overall_score}/100)>"


class URLRecord(Base):
    """Stores URLs found in analyzed emails."""
    __tablename__ = "urls"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id_fk: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(String(2048))
    domain: Mapped[Optional[str]] = mapped_column(String(255), default="")
    is_ip_based: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shortened: Mapped[bool] = mapped_column(Boolean, default=False)
    has_suspicious_tld: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    
    analysis: Mapped["AnalysisRecord"] = relationship(back_populates="urls")
    
    def __repr__(self):
        return f"<URL {self.domain}: {self.risk_score}>"


class AttachmentRecord(Base):
    """Stores attachment metadata from analyzed emails."""
    __tablename__ = "attachments"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id_fk: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"))
    filename: Mapped[str] = mapped_column(String(500))
    content_type: Mapped[Optional[str]] = mapped_column(String(100), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), default="")
    is_executable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_archive: Mapped[bool] = mapped_column(Boolean, default=False)
    
    analysis: Mapped["AnalysisRecord"] = relationship(back_populates="attachments")
    
    def __repr__(self):
        return f"<Attachment {self.filename}: {self.size} bytes>"


# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------------
async def init_db():
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Database initialized successfully")


async def get_session() -> AsyncSession:
    """Get an async database session."""
    async with async_session() as session:
        yield session
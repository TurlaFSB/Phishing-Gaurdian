"""
============================================================================
PHISHING GUARDIAN — PDF REPORT GENERATOR
============================================================================
Generates professional PDF reports from analysis results.
Light theme for readability on white paper.

Author:  worm
Version: 1.1.0 
============================================================================
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, Color
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)


class PDFReportGenerator:
    """Generates professional PDF analysis reports."""

    # Professional light theme colors
    COLOR_CRITICAL = HexColor("#C62828")
    COLOR_HIGH = HexColor("#E65100")
    COLOR_MEDIUM = HexColor("#F57C00")
    COLOR_LOW = HexColor("#1565C0")
    COLOR_SAFE = HexColor("#2E7D32")
    COLOR_WHITE = white
    COLOR_CARD = HexColor("#F5F5F5")
    COLOR_BORDER = HexColor("#BDBDBD")
    COLOR_TEXT = HexColor("#212121")
    COLOR_MUTED = HexColor("#616161")
    COLOR_TABLE_HEADER = HexColor("#E0E0E0")

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hex(color: Color) -> str:
        """Convert a reportlab Color object to a '#RRGGBB' string usable
        inside Paragraph markup (str(Color) does NOT produce this)."""
        return '#%02X%02X%02X' % (
            round(color.red * 255),
            round(color.green * 255),
            round(color.blue * 255),
        )

    @staticmethod
    def _safe(value: Any, default: str = "N/A") -> str:
        """Coerce to string, guard against None, and XML-escape so
        attacker-controlled content (subjects, filenames, URLs, etc.)
        can never break or inject into the report markup."""
        if value is None or value == "":
            return default
        return xml_escape(str(value))

    @staticmethod
    def _clamp(value: Any, lo: int = 0, hi: int = 100) -> int:
        try:
            v = int(value)
        except (TypeError, ValueError):
            return lo
        return max(lo, min(hi, v))

    def _flag_html(self, condition: bool) -> str:
        color = self._hex(self.COLOR_CRITICAL) if condition else self._hex(self.COLOR_SAFE)
        label = "DETECTED" if condition else "None"
        return f'<font color="{color}"><b>{label}</b></font>'

    def _setup_styles(self):
        """Create custom styles for professional report."""
        self.styles.add(ParagraphStyle(
            name='PG_Title',
            parent=self.styles['Title'],
            fontSize=22,
            textColor=self.COLOR_TEXT,
            spaceAfter=4,
            alignment=0,
        ))
        self.styles.add(ParagraphStyle(
            name='PG_Subtitle',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.COLOR_MUTED,
            spaceAfter=16,
            alignment=0,
        ))
        self.styles.add(ParagraphStyle(
            name='PG_SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=13,
            textColor=self.COLOR_TEXT,
            spaceBefore=18,
            spaceAfter=8,
            borderPadding=(0, 0, 2, 0),
        ))
        self.styles.add(ParagraphStyle(
            name='PG_Body',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLOR_TEXT,
            leading=15,
            spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name='PG_Indicator',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLOR_HIGH,
            leftIndent=14,
            leading=15,
            spaceAfter=3,
        ))
        self.styles.add(ParagraphStyle(
            name='PG_Meta',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=self.COLOR_MUTED,
            spaceAfter=2,
        ))
        self.styles.add(ParagraphStyle(
            name='PG_Action',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLOR_TEXT,
            leftIndent=14,
            leading=15,
            spaceAfter=3,
        ))

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def generate(self, data: Dict[str, Any], analysis_type: str = "email") -> bytes:
        """Generate professional PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=22 * mm,
            rightMargin=22 * mm,
            topMargin=22 * mm,
            bottomMargin=22 * mm,
            title="Phishing Guardian Analysis Report",
            author="Phishing Guardian",
        )

        story = []
        risk = data.get("risk_assessment") or {}
        level = str(risk.get("risk_level", "SAFE")).upper()
        score = self._clamp(risk.get("overall_score", 0))
        level_color = getattr(self, f'COLOR_{level}', self.COLOR_SAFE)
        level_hex = self._hex(level_color)

        analysis_id = self._safe(data.get("analysis_id"), "N/A")[:12]

        # ── HEADER ──────────────────────────────────────────
        story.append(Paragraph(
            "Phishing Guardian &mdash; Security Analysis Report",
            self.styles['PG_Title']
        ))
        story.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"ID: {analysis_id} | "
            f"Type: {xml_escape(str(analysis_type).upper())}",
            self.styles['PG_Subtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=self.COLOR_BORDER))
        story.append(Spacer(1, 14))

        # ── RISK SCORE ──────────────────────────────────────
        confidence = self._safe(risk.get("confidence", "LOW"))
        sources_checked = len(data.get("sources_checked") or [])
        score_data = [
            [
                Paragraph(
                    f'<font size="48"><b>{score}</b></font>'
                    f'<font size="14">/100</font>',
                    self.styles['PG_Body']
                ),
                Paragraph(
                    f'<font size="16" color="{level_hex}"><b>{level}</b></font><br/>'
                    f'<font size="10" color="{self._hex(self.COLOR_MUTED)}">'
                    f'{confidence} confidence | '
                    f'{sources_checked} sources checked'
                    f'</font>',
                    self.styles['PG_Body']
                ),
            ]
        ]
        score_table = Table(score_data, colWidths=[110, 340])
        score_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 14),
            ('RIGHTPADDING', (0, 0), (-1, -1), 14),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
            ('BACKGROUND', (0, 0), (-1, -1), self.COLOR_CARD),
            ('BOX', (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"<b>Summary:</b> {self._safe(risk.get('summary'), 'No summary available.')}",
            self.styles['PG_Body']
        ))
        story.append(Spacer(1, 16))

        # ── SUSPICIOUS INDICATORS ───────────────────────────
        indicators = risk.get("suspicious_indicators") or []
        if indicators:
            story.append(Paragraph("Suspicious Indicators", self.styles['PG_SectionHeader']))
            for ind in indicators:
                story.append(Paragraph(f"&bull; {self._safe(ind)}", self.styles['PG_Indicator']))
            story.append(Spacer(1, 12))

        # ── RECOMMENDED ACTIONS ─────────────────────────────
        actions = risk.get("recommended_actions") or []
        if actions:
            story.append(Paragraph("Recommended Actions", self.styles['PG_SectionHeader']))
            for act in actions:
                story.append(Paragraph(f"&bull; {self._safe(act)}", self.styles['PG_Action']))
            story.append(Spacer(1, 12))

        # ── SCORE BREAKDOWN ─────────────────────────────────
        breakdown = risk.get("score_breakdown") or {}
        if breakdown:
            story.append(Paragraph("Risk Score Breakdown", self.styles['PG_SectionHeader']))
            bd_data = [
                [
                    Paragraph("<b>Component</b>", self.styles['PG_Body']),
                    Paragraph("<b>Score</b>", self.styles['PG_Body']),
                    Paragraph("<b>Bar</b>", self.styles['PG_Body']),
                ]
            ]
            for label, key in [
                ("URL Analysis", "url_score"),
                ("Header Analysis", "header_score"),
                ("Domain Analysis", "domain_score"),
                ("Attachment Analysis", "attachment_score"),
                ("Heuristic Analysis", "heuristic_score"),
                ("IP Analysis", "ip_score"),
            ]:
                val = self._clamp(breakdown.get(key, 0))
                filled = val // 5
                bar = "\u2588" * filled + "\u2591" * (20 - filled)
                bd_data.append([
                    Paragraph(label, self.styles['PG_Body']),
                    Paragraph(f"<b>{val}</b>", self.styles['PG_Body']),
                    Paragraph(f'<font size="7" color="{self._hex(HexColor("#757575"))}">{bar}</font>',
                              self.styles['PG_Body']),
                ])

            bd_table = Table(bd_data, colWidths=[140, 50, 260])
            bd_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_TABLE_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ]))
            story.append(bd_table)
            story.append(Spacer(1, 14))

        # ── EMAIL DETAILS ───────────────────────────────────
        email_info = data.get("email_summary")
        if email_info and email_info.get("subject"):
            story.append(Paragraph("Email Details", self.styles['PG_SectionHeader']))
            email_data = [
                [Paragraph("<b>Field</b>", self.styles['PG_Body']),
                 Paragraph("<b>Value</b>", self.styles['PG_Body'])]
            ]
            for field, key in [
                ("Subject", "subject"), ("Sender", "sender"),
                ("Sender Domain", "sender_domain"), ("Date", "date"),
                ("URLs Found", "urls_found"), ("Attachments", "attachments_found"),
            ]:
                val = self._safe(email_info.get(key))
                email_data.append([
                    Paragraph(field, self.styles['PG_Body']),
                    Paragraph(val, self.styles['PG_Body']),
                ])
            email_table = Table(email_data, colWidths=[120, 330])
            email_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_TABLE_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ]))
            story.append(email_table)
            story.append(Spacer(1, 14))

        # ── FILE DETAILS ────────────────────────────────────
        fa = data.get("file_analysis")
        if fa:
            story.append(Paragraph("File Details", self.styles['PG_SectionHeader']))
            file_data = [
                [Paragraph("<b>Field</b>", self.styles['PG_Body']),
                 Paragraph("<b>Value</b>", self.styles['PG_Body'])]
            ]
            for field, key in [
                ("Filename", "filename"), ("File Type", "file_type"),
                ("Size", "file_size"), ("SHA256 Hash", "sha256_hash"),
            ]:
                raw_val = fa.get(key)
                if key == "file_size":
                    val = self._format_bytes(raw_val)
                else:
                    val = self._safe(raw_val)
                file_data.append([
                    Paragraph(field, self.styles['PG_Body']),
                    Paragraph(val, self.styles['PG_Body']),
                ])
            file_table = Table(file_data, colWidths=[120, 330])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_TABLE_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, -1), self.COLOR_TEXT),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ]))
            story.append(file_table)

            # VirusTotal
            vt = fa.get("virustotal") or {}
            if vt.get("checked"):
                story.append(Spacer(1, 8))
                story.append(Paragraph(
                    f"VirusTotal: <b>{self._clamp(vt.get('malicious', 0), 0, 9999)} malicious</b> / "
                    f"{self._clamp(vt.get('suspicious', 0), 0, 9999)} suspicious / "
                    f"{self._clamp(vt.get('harmless', 0), 0, 9999)} harmless "
                    f"(out of {self._clamp(vt.get('total', 0), 0, 9999)} engines)",
                    self.styles['PG_Body']
                ))

            # PDF Analysis
            pa = fa.get("pdf_analysis") or {}
            if pa.get("analyzed"):
                story.append(Spacer(1, 8))
                story.append(Paragraph("PDF Content Analysis", self.styles['PG_SectionHeader']))
                story.append(Paragraph(
                    f"&bull; JavaScript: {self._flag_html(bool(pa.get('has_javascript')))}",
                    self.styles['PG_Body']
                ))
                story.append(Paragraph(
                    f"&bull; Auto Actions: {self._flag_html(bool(pa.get('has_openaction')))}",
                    self.styles['PG_Body']
                ))
                story.append(Paragraph(
                    f"&bull; Embedded Files: {self._flag_html(bool(pa.get('has_embedded_files')))}",
                    self.styles['PG_Body']
                ))
            story.append(Spacer(1, 14))

        # ── URLS FOUND ──────────────────────────────────────
        urls = data.get("urls") or []
        if urls:
            story.append(Paragraph("URLs Detected", self.styles['PG_SectionHeader']))
            for u in urls[:10]:
                flags = []
                if u.get("is_ip_based"):
                    flags.append("IP-based")
                if u.get("is_shortened"):
                    flags.append("Shortened")
                if u.get("has_suspicious_tld"):
                    flags.append("Suspicious TLD")
                flag_str = (
                    f" <font color='{self._hex(self.COLOR_CRITICAL)}'>[{' | '.join(flags)}]</font>"
                    if flags else ""
                )
                story.append(Paragraph(
                    f"&bull; {self._safe(u.get('url'))}{flag_str}",
                    self.styles['PG_Body']
                ))
            story.append(Spacer(1, 14))

        # ── FOOTER ──────────────────────────────────────────
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=self.COLOR_BORDER))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "Phishing Guardian v1.1.0 | Free &amp; Open Source | "
            "Powered by PhishTank, OpenPhish, URLScan.io, WHOIS | "
            "Generated for authorized security assessment only",
            self.styles['PG_Meta']
        ))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def _format_bytes(self, size) -> str:
        """Format bytes to human readable. Defensive against None/garbage input."""
        try:
            size = int(size)
        except (TypeError, ValueError):
            return "0 B"
        if size < 0:
            return "0 B"
        if size < 1024:
            return f"{size} B"
        elif size < 1048576:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / 1048576:.1f} MB"
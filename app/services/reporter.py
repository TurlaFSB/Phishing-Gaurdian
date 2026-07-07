"""
============================================================================
PHISHING GUARDIAN — PDF REPORT GENERATOR
============================================================================
Generates professional PDF reports from analysis results.
Light theme for readability on white paper.

Author:  Dr. Erik
Version: 1.0.2 — FINAL
============================================================================
"""

import io
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
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

    def generate(self, data: Dict[str, Any], analysis_type: str = "email") -> bytes:
        """Generate professional PDF report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=22*mm,
            rightMargin=22*mm,
            topMargin=22*mm,
            bottomMargin=22*mm,
            title="Phishing Guardian Analysis Report",
            author="Phishing Guardian",
        )

        story = []
        risk = data.get("risk_assessment", {})
        level = risk.get("risk_level", "SAFE")
        score = risk.get("overall_score", 0)
        level_color = getattr(self, f'COLOR_{level}', self.COLOR_SAFE)

        # ── HEADER ──────────────────────────────────────────
        story.append(Paragraph(
            "Phishing Guardian — Security Analysis Report",
            self.styles['PG_Title']
        ))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | "
            f"ID: {data.get('analysis_id', 'N/A')[:12]} | "
            f"Type: {analysis_type.upper()}",
            self.styles['PG_Subtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=self.COLOR_BORDER))
        story.append(Spacer(1, 14))

        # ── RISK SCORE ──────────────────────────────────────
        score_data = [
            [
                Paragraph(
                    f'<font size="48"><b>{score}</b></font>'
                    f'<font size="14">/100</font>',
                    self.styles['PG_Body']
                ),
                Paragraph(
                    f'<font size="16" color="{level_color}"><b>{level}</b></font><br/>'
                    f'<font size="10" color="#616161">'
                    f'{risk.get("confidence", "LOW")} confidence | '
                    f'{len(data.get("sources_checked", []))} sources checked'
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
            ('ROUNDEDCORNERS', [4, 4, 4, 4]),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"<b>Summary:</b> {risk.get('summary', 'No summary available.')}",
            self.styles['PG_Body']
        ))
        story.append(Spacer(1, 16))

        # ── SUSPICIOUS INDICATORS ───────────────────────────
        indicators = risk.get("suspicious_indicators", [])
        if indicators:
            story.append(Paragraph("🔴 Suspicious Indicators", self.styles['PG_SectionHeader']))
            for ind in indicators:
                story.append(Paragraph(f"• {ind}", self.styles['PG_Indicator']))
            story.append(Spacer(1, 12))

        # ── RECOMMENDED ACTIONS ─────────────────────────────
        actions = risk.get("recommended_actions", [])
        if actions:
            story.append(Paragraph("📋 Recommended Actions", self.styles['PG_SectionHeader']))
            for act in actions:
                story.append(Paragraph(f"• {act}", self.styles['PG_Action']))
            story.append(Spacer(1, 12))

        # ── SCORE BREAKDOWN ─────────────────────────────────
        breakdown = risk.get("score_breakdown", {})
        if breakdown:
            story.append(Paragraph("📊 Risk Score Breakdown", self.styles['PG_SectionHeader']))
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
                val = breakdown.get(key, 0)
                bar = "█" * int(val / 5) + "░" * (20 - int(val / 5))
                bd_data.append([
                    Paragraph(label, self.styles['PG_Body']),
                    Paragraph(f"<b>{val}</b>", self.styles['PG_Body']),
                    Paragraph(f'<font size="7" color="#757575">{bar}</font>', self.styles['PG_Body']),
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
            story.append(Paragraph("📧 Email Details", self.styles['PG_SectionHeader']))
            email_data = [
                [Paragraph("<b>Field</b>", self.styles['PG_Body']),
                 Paragraph("<b>Value</b>", self.styles['PG_Body'])]
            ]
            for field, key in [
                ("Subject", "subject"), ("Sender", "sender"),
                ("Sender Domain", "sender_domain"), ("Date", "date"),
                ("URLs Found", "urls_found"), ("Attachments", "attachments_found"),
            ]:
                val = email_info.get(key, "N/A")
                email_data.append([
                    Paragraph(field, self.styles['PG_Body']),
                    Paragraph(str(val), self.styles['PG_Body']),
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
            story.append(Paragraph("📄 File Details", self.styles['PG_SectionHeader']))
            file_data = [
                [Paragraph("<b>Field</b>", self.styles['PG_Body']),
                 Paragraph("<b>Value</b>", self.styles['PG_Body'])]
            ]
            for field, key in [
                ("Filename", "filename"), ("File Type", "file_type"),
                ("Size", "file_size"), ("SHA256 Hash", "sha256_hash"),
            ]:
                val = fa.get(key, "N/A")
                if key == "file_size":
                    val = self._format_bytes(val)
                file_data.append([
                    Paragraph(field, self.styles['PG_Body']),
                    Paragraph(str(val), self.styles['PG_Body']),
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
            vt = fa.get("virustotal", {})
            if vt.get("checked"):
                story.append(Spacer(1, 8))
                story.append(Paragraph(
                    f"🦠 VirusTotal: <b>{vt.get('malicious', 0)} malicious</b> / "
                    f"{vt.get('suspicious', 0)} suspicious / "
                    f"{vt.get('harmless', 0)} harmless "
                    f"(out of {vt.get('total', 0)} engines)",
                    self.styles['PG_Body']
                ))

            # PDF Analysis
            pa = fa.get("pdf_analysis", {})
            if pa.get("analyzed"):
                story.append(Spacer(1, 8))
                story.append(Paragraph("PDF Content Analysis", self.styles['PG_SectionHeader']))
                story.append(Paragraph(
                    f"• JavaScript: {'<font color=\"#C62828\"><b>⚠️ DETECTED</b></font>' if pa.get('has_javascript') else '<font color=\"#2E7D32\"><b>✅ None</b></font>'}",
                    self.styles['PG_Body']
                ))
                story.append(Paragraph(
                    f"• Auto Actions: {'<font color=\"#C62828\"><b>⚠️ DETECTED</b></font>' if pa.get('has_openaction') else '<font color=\"#2E7D32\"><b>✅ None</b></font>'}",
                    self.styles['PG_Body']
                ))
                story.append(Paragraph(
                    f"• Embedded Files: {'<font color=\"#C62828\"><b>⚠️ DETECTED</b></font>' if pa.get('has_embedded_files') else '<font color=\"#2E7D32\"><b>✅ None</b></font>'}",
                    self.styles['PG_Body']
                ))
            story.append(Spacer(1, 14))

        # ── URLS FOUND ──────────────────────────────────────
        urls = data.get("urls", [])
        if urls:
            story.append(Paragraph("🔗 URLs Detected", self.styles['PG_SectionHeader']))
            for u in urls[:10]:
                flags = []
                if u.get("is_ip_based"):
                    flags.append("IP-based")
                if u.get("is_shortened"):
                    flags.append("Shortened")
                if u.get("has_suspicious_tld"):
                    flags.append("Suspicious TLD")
                flag_str = f" <font color='#C62828'>[{' | '.join(flags)}]</font>" if flags else ""
                story.append(Paragraph(
                    f"• {u.get('url', 'N/A')}{flag_str}",
                    self.styles['PG_Body']
                ))
            story.append(Spacer(1, 14))

        # ── FOOTER ──────────────────────────────────────────
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=self.COLOR_BORDER))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "Phishing Guardian v1.0.0 | Free & Open Source | "
            "Powered by PhishTank, OpenPhish, URLScan.io, WHOIS | "
            "Generated for authorized security assessment only",
            self.styles['PG_Meta']
        ))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def _format_bytes(self, size) -> str:
        """Format bytes to human readable."""
        if not size:
            return "0 B"
        size = int(size)
        if size < 1024:
            return f"{size} B"
        elif size < 1048576:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / 1048576:.1f} MB"
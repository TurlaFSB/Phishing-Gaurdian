/**
 * ============================================================================
 * PHISHING GUARDIAN — MAIN APPLICATION
 * Handles email analysis, file analysis, history, and UI interactions
 * Author: Dr. Erik | Version: 1.1.0
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// DOM ELEMENTS
// ---------------------------------------------------------------------------
const elements = {
    emailInput: document.getElementById('emailInput'),
    analyzeBtn: document.getElementById('analyzeBtn'),
    clearBtn: document.getElementById('clearBtn'),
    loadingOverlay: document.getElementById('loadingOverlay'),
    resultContainer: document.getElementById('resultContainer'),
    resultContent: document.getElementById('resultContent'),
    historyTableBody: document.getElementById('historyTableBody'),
    historySearch: document.getElementById('historySearch'),
    emptyState: document.getElementById('emptyState'),
};

// ---------------------------------------------------------------------------
// EMAIL ANALYSIS
// ---------------------------------------------------------------------------
async function analyzeEmail() {
    const email = elements.emailInput?.value;
    if (!email || !email.trim()) {
        showToast('Please paste an email first', 'warning');
        return;
    }

    showLoading(true);
    hideResult();

    try {
        const formData = new FormData();
        formData.append('raw_email', email);

        const response = await fetch('/api/v1/analyze', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail?.message || errorData.detail?.error || 'Analysis failed');
        }

        const data = await response.json();
        renderResult(data);
        saveToLocalHistory(data);

    } catch (error) {
        showResultError(error.message);
    } finally {
        showLoading(false);
        if (elements.analyzeBtn) {
            elements.analyzeBtn.disabled = false;
            elements.analyzeBtn.textContent = '🔍 Analyze Email';
        }
    }
}

// ---------------------------------------------------------------------------
// FILE ANALYSIS
// ---------------------------------------------------------------------------
let selectedFile = null;

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;
    selectedFile = file;
    
    const fileNameEl = document.getElementById('fileName');
    const fileSizeEl = document.getElementById('fileSize');
    const fileInfoEl = document.getElementById('fileInfo');
    const analyzeFileBtn = document.getElementById('analyzeFileBtn');
    const dropZone = document.getElementById('dropZone');
    
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = formatFileSize(file.size);
    if (fileInfoEl) fileInfoEl.classList.add('visible');
    if (analyzeFileBtn) analyzeFileBtn.disabled = false;
    if (dropZone) dropZone.style.display = 'none';
}

function removeFile() {
    selectedFile = null;
    const fileInput = document.getElementById('fileInput');
    const fileInfoEl = document.getElementById('fileInfo');
    const analyzeFileBtn = document.getElementById('analyzeFileBtn');
    const dropZone = document.getElementById('dropZone');
    
    if (fileInput) fileInput.value = '';
    if (fileInfoEl) fileInfoEl.classList.remove('visible');
    if (analyzeFileBtn) analyzeFileBtn.disabled = true;
    if (dropZone) dropZone.style.display = 'block';
}

function formatFileSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

async function analyzeFile() {
    if (!selectedFile) {
        alert('Please select a file first');
        return;
    }

    const btn = document.getElementById('analyzeFileBtn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '⏳ Analyzing...';
    }
    
    const loadingText = document.getElementById('loadingText');
    if (loadingText) loadingText.textContent = 'Analyzing file with threat intelligence...';
    
    showLoading(true);
    hideResult();

    try {
        const formData = new FormData();
        formData.append('uploaded_file', selectedFile);

        const response = await fetch('/api/v1/analyze', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail?.message || err.detail?.error || 'Analysis failed');
        }

        const data = await response.json();
        
        if (data.analysis_type === 'file') {
            renderFileResult(data);
        } else {
            renderResult(data);
        }

    } catch (e) {
        showResultError(e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🔍 Analyze File';
        }
        showLoading(false);
    }
}

function renderFileResult(data) {
    const fa = data.file_analysis || {};
    const level = (fa.risk_level || 'SAFE').toLowerCase();
    const score = fa.risk_score || 0;
    const indicators = fa.suspicious_indicators || [];
    const actions = fa.recommended_actions || [];
    const vt = fa.virustotal || {};

    let html = `<div class="result-card ${level}">`;
    html += `<div class="score-display score-${level}">`;
    html += `<div class="score-number">${score}<span style="font-size:0.4em">/100</span></div>`;
    html += `<div class="score-label">${fa.risk_level || 'UNKNOWN'}</div></div>`;
    html += `<div class="result-summary">📄 ${escapeHtml(fa.filename || 'Unknown')} (${formatFileSize(fa.file_size || 0)})</div>`;
    html += `<div class="result-meta">`;
    html += `<span>📁 ${fa.file_type || 'unknown'}</span>`;
    if (vt.checked) html += `<span>🦠 VT: ${vt.malicious}/${vt.total}</span>`;
    html += `<span>🔑 ${(fa.sha256_hash || '').substring(0, 16)}...</span>`;
    html += `</div>`;

    if (indicators.length > 0) {
        html += `<div class="result-section"><h3>🔴 Indicators</h3><ul class="indicator-danger">`;
        html += indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('');
        html += `</ul></div>`;
    }
    if (actions.length > 0) {
        html += `<div class="result-section"><h3>📋 Actions</h3><ul>`;
        html += actions.map(a => `<li>${escapeHtml(a)}</li>`).join('');
        html += `</ul></div>`;
    }
    if (fa.pdf_analysis && fa.pdf_analysis.analyzed) {
        const pa = fa.pdf_analysis;
        html += `<div class="result-section"><h3>📄 PDF Analysis</h3><ul>`;
        html += `<li>JavaScript: ${pa.has_javascript ? '⚠️ DETECTED' : '✅ None'}</li>`;
        html += `<li>Auto Actions: ${pa.has_openaction ? '⚠️ DETECTED' : '✅ None'}</li>`;
        html += `<li>Embedded Files: ${pa.has_embedded_files ? '⚠️ DETECTED' : '✅ None'}</li>`;
        html += `</ul></div>`;
    }
    html += `</div>`;

    const resultContent = document.getElementById('resultContent');
    const resultContainer = document.getElementById('resultContainer');
    if (resultContent) resultContent.innerHTML = html;
    if (resultContainer) resultContainer.classList.add('visible');
}

// ---------------------------------------------------------------------------
// RENDER FUNCTIONS
// ---------------------------------------------------------------------------
function renderResult(data) {
    const risk = data.risk_assessment || {};
    const score = risk.overall_score ?? 0;
    const level = (risk.risk_level || 'SAFE').toLowerCase();
    const summary = risk.summary || 'Analysis complete.';
    const confidence = risk.confidence || 'LOW';
    const indicators = risk.suspicious_indicators || [];
    const actions = risk.recommended_actions || [];
    const breakdown = risk.score_breakdown || {};
    const sources = data.sources_checked || [];
    const emailInfo = data.email_summary || {};
    const time = data.analysis_time_seconds || 0;

    const html = `
        <div class="result-card ${level}">
            <div class="score-display score-${level}">
                <div class="score-number">${score}<span style="font-size:0.4em">/100</span></div>
                <div class="score-label">${risk.risk_level || 'UNKNOWN'}</div>
            </div>
            <div class="result-summary">${escapeHtml(summary)}</div>
            <div class="result-meta">
                <span>🔍 ${sources.length} sources</span>
                <span>📊 ${confidence} confidence</span>
                <span>⏱️ ${time}s</span>
            </div>
            ${indicators.length > 0 ? `
            <div class="result-section"><h3>🔴 Indicators</h3><ul class="indicator-danger">
                ${indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
            </ul></div>` : ''}
            ${actions.length > 0 ? `
            <div class="result-section"><h3>📋 Actions</h3><ul>
                ${actions.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
            </ul></div>` : ''}
            <div class="result-section"><h3>📊 Score Breakdown</h3><ul>
                <li>🔗 URL: <strong>${breakdown.url_score ?? 0}</strong></li>
                <li>📧 Header: <strong>${breakdown.header_score ?? 0}</strong></li>
                <li>🌐 Domain: <strong>${breakdown.domain_score ?? 0}</strong></li>
                <li>📎 Attachment: <strong>${breakdown.attachment_score ?? 0}</strong></li>
                <li>🧠 Heuristic: <strong>${breakdown.heuristic_score ?? 0}</strong></li>
                <li>📍 IP: <strong>${breakdown.ip_score ?? 0}</strong></li>
            </ul></div>
            ${emailInfo.subject ? `
            <div class="result-section"><h3>📧 Email Details</h3><ul>
                <li>Subject: ${escapeHtml(emailInfo.subject)}</li>
                <li>From: ${escapeHtml(emailInfo.sender || 'N/A')}</li>
                <li>Domain: ${escapeHtml(emailInfo.sender_domain || 'N/A')}</li>
                <li>URLs: ${emailInfo.urls_found ?? 0}</li>
                <li>Attachments: ${emailInfo.attachments_found ?? 0}</li>
            </ul></div>` : ''}
        </div>`;

    if (elements.resultContent) elements.resultContent.innerHTML = html;
    if (elements.resultContainer) elements.resultContainer.classList.add('visible');
}

function showResultError(message) {
    if (elements.resultContent) {
        elements.resultContent.innerHTML = `
            <div class="result-card critical">
                <div style="text-align:center;color:var(--accent-red);">
                    <h3>❌ Analysis Failed</h3>
                    <p>${escapeHtml(message)}</p>
                </div>
            </div>`;
    }
    if (elements.resultContainer) elements.resultContainer.classList.add('visible');
}

// ---------------------------------------------------------------------------
// UI HELPERS
// ---------------------------------------------------------------------------
function showLoading(show) {
    if (elements.loadingOverlay) {
        elements.loadingOverlay.classList.toggle('visible', show);
    }
    if (elements.analyzeBtn) {
        elements.analyzeBtn.disabled = show;
        elements.analyzeBtn.textContent = show ? '⏳ Analyzing...' : '🔍 Analyze Email';
    }
}

function hideResult() {
    if (elements.resultContainer) {
        elements.resultContainer.classList.remove('visible');
    }
}

function clearAll() {
    if (elements.emailInput) elements.emailInput.value = '';
    removeFile();
    hideResult();
    if (elements.loadingOverlay) elements.loadingOverlay.classList.remove('visible');
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed; bottom: 20px; right: 20px;
        background: var(--bg-secondary); color: var(--text-primary);
        border: 1px solid var(--border-primary);
        padding: 12px 20px; border-radius: var(--radius-md);
        z-index: 1000; animation: slideUp 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// ---------------------------------------------------------------------------
// LOCAL HISTORY
// ---------------------------------------------------------------------------
function saveToLocalHistory(data) {
    try {
        const history = JSON.parse(localStorage.getItem('phishing_guardian_history') || '[]');
        history.unshift({
            id: data.analysis_id,
            timestamp: data.timestamp || new Date().toISOString(),
            subject: data.email_summary?.subject || 'No Subject',
            sender: data.email_summary?.sender || 'Unknown',
            score: data.risk_assessment?.overall_score || 0,
            level: data.risk_assessment?.risk_level || 'SAFE',
        });
        if (history.length > 50) history.length = 50;
        localStorage.setItem('phishing_guardian_history', JSON.stringify(history));
        renderHistoryTable();
    } catch (e) {}
}

function loadHistory() {
    try {
        return JSON.parse(localStorage.getItem('phishing_guardian_history') || '[]');
    } catch (e) {
        return [];
    }
}

function renderHistoryTable() {
    const history = loadHistory();
    const tbody = elements.historyTableBody;
    const empty = elements.emptyState;
    
    if (!tbody) return;
    if (history.length === 0) {
        if (empty) empty.style.display = 'block';
        tbody.innerHTML = '';
        return;
    }
    if (empty) empty.style.display = 'none';

    const searchTerm = (elements.historySearch?.value || '').toLowerCase();
    const filtered = searchTerm
        ? history.filter(h => h.subject.toLowerCase().includes(searchTerm) || h.sender.toLowerCase().includes(searchTerm))
        : history;

    tbody.innerHTML = filtered.map(h => `
        <tr>
            <td>${new Date(h.timestamp).toLocaleDateString()}</td>
            <td>${escapeHtml(h.subject)}</td>
            <td>${escapeHtml(h.sender)}</td>
            <td><span class="badge-risk badge-${h.level.toLowerCase()}">${h.level}</span></td>
            <td><strong>${h.score}/100</strong></td>
        </tr>
    `).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No results found</td></tr>';
}

// ---------------------------------------------------------------------------
// UTILITY
// ---------------------------------------------------------------------------
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// INITIALIZATION
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    if (elements.analyzeBtn) elements.analyzeBtn.addEventListener('click', analyzeEmail);
    if (elements.clearBtn) elements.clearBtn.addEventListener('click', clearAll);
    if (elements.historySearch) elements.historySearch.addEventListener('input', renderHistoryTable);
    renderHistoryTable();

    if (elements.emailInput) {
        elements.emailInput.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') analyzeEmail();
        });
    }
});
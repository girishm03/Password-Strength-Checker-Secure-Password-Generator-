/**
 * CyberShield Frontend Application Logic
 * Communicates with FastAPI backend for deep analysis and CSPRNG generation.
 * Includes graceful client-side fallback if opened directly without a running backend.
 */

// Global State
const state = {
    currentTab: 'tab-auditor',
    generatorMode: 'random',
    lastGeneratedPassword: '',
    isBackendOnline: false,
    debounceTimer: null,
};

// DOM Elements
const elements = {
    // Navigation
    tabs: document.querySelectorAll('.nav-tab'),
    tabContents: document.querySelectorAll('.tab-content'),
    connectionStatus: document.getElementById('connection-status'),
    statusPulse: document.querySelector('.status-pulse'),

    // Strength Auditor
    passwordInput: document.getElementById('password-input'),
    toggleMaskBtn: document.getElementById('toggle-mask-btn'),
    maskIcon: document.getElementById('mask-icon'),
    clearInputBtn: document.getElementById('clear-input-btn'),
    checkHibpToggle: document.getElementById('check-hibp-toggle'),
    sampleChips: document.querySelectorAll('.sample-chip'),

    // Auditor Outputs
    scoreMeterCircle: document.getElementById('score-meter-circle'),
    scoreNumber: document.getElementById('score-number'),
    scoreTitle: document.getElementById('score-title'),
    ratingBadge: document.getElementById('rating-badge'),
    nistBadge: document.getElementById('nist-badge'),
    metricLength: document.getElementById('metric-length'),
    metricEntropy: document.getElementById('metric-entropy'),
    metricPool: document.getElementById('metric-pool'),
    metricClasses: document.getElementById('metric-classes'),
    breachCard: document.getElementById('breach-card'),
    breachIcon: document.getElementById('breach-icon'),
    breachTitle: document.getElementById('breach-title'),
    breachDesc: document.getElementById('breach-desc'),
    crackOnlineSlow: document.getElementById('crack-online-slow'),
    crackOnlineFast: document.getElementById('crack-online-fast'),
    crackGpuSingle: document.getElementById('crack-gpu-single'),
    crackGpuCluster: document.getElementById('crack-gpu-cluster'),
    barLower: document.getElementById('bar-lower'),
    barUpper: document.getElementById('bar-upper'),
    barDigits: document.getElementById('bar-digits'),
    barSymbols: document.getElementById('bar-symbols'),
    countLower: document.getElementById('count-lower'),
    countUpper: document.getElementById('count-upper'),
    countDigits: document.getElementById('count-digits'),
    countSymbols: document.getElementById('count-symbols'),
    vulnerabilitiesList: document.getElementById('vulnerabilities-list'),
    recommendationsList: document.getElementById('recommendations-list'),

    // Secure Generator
    modePills: document.querySelectorAll('.mode-pill'),
    genPanels: document.querySelectorAll('.gen-panel'),
    genLenSlider: document.getElementById('gen-len-slider'),
    genLenVal: document.getElementById('gen-len-val'),
    genLower: document.getElementById('gen-lower'),
    genUpper: document.getElementById('gen-upper'),
    genDigits: document.getElementById('gen-digits'),
    genSymbols: document.getElementById('gen-symbols'),
    genNoAmbig: document.getElementById('gen-no-ambig'),

    genWordsSlider: document.getElementById('gen-words-slider'),
    genWordsVal: document.getElementById('gen-words-val'),
    genSeparator: document.getElementById('gen-separator'),
    genCapitalize: document.getElementById('gen-capitalize'),
    genAddNumber: document.getElementById('gen-add-number'),
    genAddSymbol: document.getElementById('gen-add-symbol'),

    genPinLenSlider: document.getElementById('gen-pin-len-slider'),
    genPinLenVal: document.getElementById('gen-pin-len-val'),
    genBlocksSlider: document.getElementById('gen-blocks-slider'),
    genBlocksVal: document.getElementById('gen-blocks-val'),
    genBlockLenSlider: document.getElementById('gen-block-len-slider'),
    genBlockLenVal: document.getElementById('gen-block-len-val'),

    triggerGenerateBtn: document.getElementById('trigger-generate-btn'),
    generatedPasswordText: document.getElementById('generated-password-text'),
    copyGeneratedBtn: document.getElementById('copy-generated-btn'),
    genRatingBadge: document.getElementById('gen-rating-badge'),
    genStatLen: document.getElementById('gen-stat-len'),
    genStatEntropy: document.getElementById('gen-stat-entropy'),
    genStatPool: document.getElementById('gen-stat-pool'),
    sendToAuditorBtn: document.getElementById('send-to-auditor-btn'),

    // Bulk Auditor
    bulkTextarea: document.getElementById('bulk-textarea'),
    bulkHibpToggle: document.getElementById('bulk-hibp-toggle'),
    runBulkBtn: document.getElementById('run-bulk-btn'),
    bulkSummaryContainer: document.getElementById('bulk-summary-container'),
    bulkStatTotal: document.getElementById('bulk-stat-total'),
    bulkStatAvg: document.getElementById('bulk-stat-avg'),
    bulkStatCompliant: document.getElementById('bulk-stat-compliant'),
    bulkStatWeak: document.getElementById('bulk-stat-weak'),
    bulkTableContainer: document.getElementById('bulk-table-container'),
    bulkTableBody: document.getElementById('bulk-table-body'),

    // Toast
    toastContainer: document.getElementById('toast-container'),
};

const CIRCUMFERENCE = 414.69; // 2 * PI * 66

// ==========================================================================
// Initialization & Backend Connectivity Check
// ==========================================================================
async function initApp() {
    setupTabNavigation();
    setupAuditorEvents();
    setupGeneratorEvents();
    setupBulkAuditorEvents();

    await checkBackendStatus();

    // Run initial analysis and password generation
    elements.passwordInput.value = "Admin@2026_Secure!";
    triggerAnalysis();
    generatePassword();
}

async function checkBackendStatus() {
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: 'test', check_breach: false }),
        });
        if (response.ok) {
            state.isBackendOnline = true;
            elements.connectionStatus.textContent = "Engine Connected";
            elements.statusPulse.className = "status-pulse online";
            return true;
        }
    } catch (e) {
        state.isBackendOnline = false;
        elements.connectionStatus.textContent = "Offline Mode";
        elements.statusPulse.className = "status-pulse offline";
        console.warn("Backend API not reachable. Using client-side security heuristics.");
        return false;
    }
}

// ==========================================================================
// Navigation & Tabs
// ==========================================================================
function setupTabNavigation() {
    elements.tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.getAttribute('data-tab');
            switchTab(targetId);
        });
    });
}

function switchTab(tabId) {
    elements.tabs.forEach(t => {
        t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
    });
    elements.tabContents.forEach(content => {
        content.classList.toggle('active', content.id === tabId);
    });
    state.currentTab = tabId;
}

// ==========================================================================
// Toast Notifications
// ==========================================================================
function showToast(message, icon = "✅") {
    const toast = document.createElement('div');
    toast.className = 'cyber-toast';
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    elements.toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// ==========================================================================
// TAB 1: Password Strength Auditor
// ==========================================================================
function setupAuditorEvents() {
    elements.passwordInput.addEventListener('input', () => {
        clearTimeout(state.debounceTimer);
        state.debounceTimer = setTimeout(() => {
            triggerAnalysis();
        }, 150);
    });

    elements.checkHibpToggle.addEventListener('change', () => {
        triggerAnalysis();
    });

    elements.toggleMaskBtn.addEventListener('click', () => {
        const currentType = elements.passwordInput.type;
        if (currentType === 'password') {
            elements.passwordInput.type = 'text';
            elements.maskIcon.textContent = '🔒';
        } else {
            elements.passwordInput.type = 'password';
            elements.maskIcon.textContent = '👁️';
        }
    });

    elements.clearInputBtn.addEventListener('click', () => {
        elements.passwordInput.value = '';
        triggerAnalysis();
        elements.passwordInput.focus();
    });

    elements.sampleChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const pwd = chip.getAttribute('data-pwd');
            elements.passwordInput.value = pwd;
            triggerAnalysis();
        });
    });
}

async function triggerAnalysis() {
    const password = elements.passwordInput.value;
    const checkBreach = elements.checkHibpToggle.checked;

    if (!password) {
        renderEmptyAnalysis();
        return;
    }

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, check_breach: checkBreach }),
        });
        if (res.ok) {
            const data = await res.json();
            renderAnalysisResults(data);
            return;
        }
    } catch (err) {
        console.warn("Backend error, falling back to client evaluation:", err);
    }

    // Client-side fallback evaluation
    renderClientSideFallback(password);
}

function renderAnalysisResults(data) {
    const score = data.score;
    const rating = data.rating;

    // Update Circle Meter
    elements.scoreNumber.textContent = score;
    elements.scoreTitle.textContent = getScoreDescription(rating);
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    elements.scoreMeterCircle.style.strokeDashoffset = offset;

    // Score Color
    const color = getRatingColor(rating);
    elements.scoreMeterCircle.style.stroke = color;

    // Rating Badge
    elements.ratingBadge.textContent = rating.toUpperCase();
    elements.ratingBadge.className = `cyber-badge badge-${rating.toLowerCase().replace(' ', '-')}`;

    // NIST Tag
    if (data.nist_compliant) {
        elements.nistBadge.className = 'nist-tag compliant';
        elements.nistBadge.innerHTML = '✅ NIST SP 800-63B: Compliant';
    } else {
        elements.nistBadge.className = 'nist-tag non-compliant';
        elements.nistBadge.innerHTML = '⚠️ NIST SP 800-63B: Non-Compliant';
    }

    // Metric counters
    elements.metricLength.innerHTML = `${data.length} <span class="metric-unit">chars</span>`;
    elements.metricEntropy.innerHTML = `${data.entropy.entropy_bits} <span class="metric-unit">bits</span>`;
    elements.metricPool.innerHTML = `${data.entropy.pool_size} <span class="metric-unit">symbols</span>`;

    const activeClasses = [
        data.char_counts.lower > 0,
        data.char_counts.upper > 0,
        data.char_counts.digits > 0,
        data.char_counts.symbols > 0
    ].filter(Boolean).length;
    elements.metricClasses.innerHTML = `${activeClasses} <span class="metric-unit">/ 4</span>`;

    // Breach Banner
    if (data.is_breached) {
        elements.breachCard.className = 'cyber-card breach-card breached';
        elements.breachIcon.textContent = '🚨';
        elements.breachTitle.textContent = 'COMPROMISED IN DATA BREACH!';
        elements.breachDesc.textContent = `${data.breach_status_message} Credential stuffing bots have this password on file.`;
    } else {
        elements.breachCard.className = 'cyber-card breach-card clean';
        elements.breachIcon.textContent = '🛡️';
        elements.breachTitle.textContent = 'Breach Verification Clean';
        elements.breachDesc.textContent = data.breach_status_message || 'Zero records detected in HaveIBeenPwned database.';
    }

    // Crack Times
    const times = data.entropy.crack_times;
    if (times) {
        elements.crackOnlineSlow.textContent = times.online_throttled ? times.online_throttled.formatted : 'Instant';
        elements.crackOnlineFast.textContent = times.online_fast ? times.online_fast.formatted : 'Instant';
        elements.crackGpuSingle.textContent = times.offline_single_gpu ? times.offline_single_gpu.formatted : 'Instant';
        elements.crackGpuCluster.textContent = times.offline_rig_cluster ? times.offline_rig_cluster.formatted : 'Instant';
    }

    // Character Composition Bars
    const totalChars = Math.max(1, data.length);
    renderCompBar(elements.barLower, elements.countLower, data.char_counts.lower, totalChars);
    renderCompBar(elements.barUpper, elements.countUpper, data.char_counts.upper, totalChars);
    renderCompBar(elements.barDigits, elements.countDigits, data.char_counts.digits, totalChars);
    renderCompBar(elements.barSymbols, elements.countSymbols, data.char_counts.symbols, totalChars);

    // Vulnerabilities List
    elements.vulnerabilitiesList.innerHTML = '';
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        data.vulnerabilities.forEach(v => {
            const item = document.createElement('div');
            item.className = `finding-item sev-${v.severity.toLowerCase()}`;
            item.innerHTML = `
                <div class="finding-header">
                    <span class="sev-badge">${v.severity}</span>
                    <span>${escapeHtml(v.title)}</span>
                </div>
                <div class="finding-desc">${escapeHtml(v.description)}</div>
            `;
            elements.vulnerabilitiesList.appendChild(item);
        });
    } else {
        elements.vulnerabilitiesList.innerHTML = `
            <div class="finding-item sev-low">
                <div class="finding-header">
                    <span class="sev-badge">OK</span>
                    <span>No critical patterns or sequences detected</span>
                </div>
                <div class="finding-desc">Password avoids trivial keyboard walks, sequential chars, and common dictionary passwords.</div>
            </div>
        `;
    }

    // Recommendations List
    elements.recommendationsList.innerHTML = '';
    if (data.suggestions && data.suggestions.length > 0) {
        data.suggestions.forEach(s => {
            const li = document.createElement('li');
            li.textContent = s;
            elements.recommendationsList.appendChild(li);
        });
    }
}

function renderCompBar(barEl, countEl, count, total) {
    const pct = Math.round((count / total) * 100);
    barEl.style.width = `${pct}%`;
    countEl.textContent = count;
}

function renderEmptyAnalysis() {
    elements.scoreNumber.textContent = '0';
    elements.scoreTitle.textContent = 'Enter a password to evaluate';
    elements.scoreMeterCircle.style.strokeDashoffset = CIRCUMFERENCE;
    elements.ratingBadge.textContent = 'NO INPUT';
    elements.ratingBadge.className = 'cyber-badge badge-weak';
    elements.nistBadge.className = 'nist-tag non-compliant';
    elements.nistBadge.textContent = '⚠️ NIST SP 800-63B: Waiting for input';
    elements.metricLength.innerHTML = '0 <span class="metric-unit">chars</span>';
    elements.metricEntropy.innerHTML = '0.0 <span class="metric-unit">bits</span>';
    elements.metricPool.innerHTML = '0 <span class="metric-unit">symbols</span>';
    elements.metricClasses.innerHTML = '0 <span class="metric-unit">/ 4</span>';
    elements.crackOnlineSlow.textContent = 'Instant';
    elements.crackOnlineFast.textContent = 'Instant';
    elements.crackGpuSingle.textContent = 'Instant';
    elements.crackGpuCluster.textContent = 'Instant';
    elements.vulnerabilitiesList.innerHTML = '<div style="color:var(--text-dim); font-size:0.85rem;">No analysis to display.</div>';
    elements.recommendationsList.innerHTML = '<li>Type or paste a password above to view detailed recommendations.</li>';
}

function getRatingColor(rating) {
    switch (rating) {
        case 'Very Strong': return '#00ff9d';
        case 'Strong': return '#34d399';
        case 'Fair': return '#ffb800';
        case 'Weak': return '#f87171';
        default: return '#ff4d4d';
    }
}

function getScoreDescription(rating) {
    switch (rating) {
        case 'Very Strong': return 'Exceptional Cryptographic Defense';
        case 'Strong': return 'Robust Security Posture';
        case 'Fair': return 'Moderate Defense - Needs Expansion';
        case 'Weak': return 'Vulnerable to Offline Cracking';
        default: return 'Critical Risk - Trivial to Crack';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==========================================================================
// TAB 2: Secure Password Generator
// ==========================================================================
function setupGeneratorEvents() {
    // Mode switcher
    elements.modePills.forEach(pill => {
        pill.addEventListener('click', () => {
            const mode = pill.getAttribute('data-mode');
            state.generatorMode = mode;
            elements.modePills.forEach(p => p.classList.toggle('active', p === pill));
            elements.genPanels.forEach(panel => {
                panel.classList.toggle('active', panel.id === `panel-${mode}`);
            });
            generatePassword();
        });
    });

    // Slider value sync
    elements.genLenSlider.addEventListener('input', (e) => {
        elements.genLenVal.textContent = e.target.value;
        generatePassword();
    });

    elements.genWordsSlider.addEventListener('input', (e) => {
        elements.genWordsVal.textContent = e.target.value;
        generatePassword();
    });

    elements.genPinLenSlider.addEventListener('input', (e) => {
        elements.genPinLenVal.textContent = e.target.value;
        generatePassword();
    });

    elements.genBlocksSlider.addEventListener('input', (e) => {
        elements.genBlocksVal.textContent = e.target.value;
        generatePassword();
    });

    elements.genBlockLenSlider.addEventListener('input', (e) => {
        elements.genBlockLenVal.textContent = e.target.value;
        generatePassword();
    });

    // Checkbox toggles
    [
        elements.genLower, elements.genUpper, elements.genDigits, elements.genSymbols, elements.genNoAmbig,
        elements.genSeparator, elements.genCapitalize, elements.genAddNumber, elements.genAddSymbol
    ].forEach(input => {
        if (input) input.addEventListener('change', () => generatePassword());
    });

    // Buttons
    elements.triggerGenerateBtn.addEventListener('click', () => generatePassword());

    elements.copyGeneratedBtn.addEventListener('click', () => {
        const text = state.lastGeneratedPassword || elements.generatedPasswordText.textContent;
        navigator.clipboard.writeText(text).then(() => {
            showToast('Credential copied to clipboard!', '📋');
        }).catch(() => {
            showToast('Unable to copy to clipboard', '⚠️');
        });
    });

    elements.sendToAuditorBtn.addEventListener('click', () => {
        const text = state.lastGeneratedPassword || elements.generatedPasswordText.textContent;
        elements.passwordInput.value = text;
        switchTab('tab-auditor');
        triggerAnalysis();
        showToast('Transferred to Strength Auditor', '🔍');
    });
}

async function generatePassword() {
    const payload = {
        mode: state.generatorMode,
        length: parseInt(elements.genLenSlider.value, 10),
        use_lower: elements.genLower.checked,
        use_upper: elements.genUpper.checked,
        use_digits: elements.genDigits.checked,
        use_symbols: elements.genSymbols.checked,
        exclude_ambiguous: elements.genNoAmbig.checked,
        num_words: parseInt(elements.genWordsSlider.value, 10),
        separator: elements.genSeparator.value,
        capitalize: elements.genCapitalize.checked,
        include_number: elements.genAddNumber.checked,
        include_symbol: elements.genAddSymbol.checked,
        block_count: parseInt(elements.genBlocksSlider.value, 10),
        block_length: parseInt(elements.genBlockLenSlider.value, 10),
    };

    if (state.generatorMode === 'pin') {
        payload.length = parseInt(elements.genPinLenSlider.value, 10);
    }

    try {
        const res = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            const data = await res.json();
            renderGeneratedResult(data);
            return;
        }
    } catch (err) {
        console.warn("Backend generate error, using client fallback:", err);
    }

    // Client fallback generation
    clientFallbackGenerate(payload);
}

function renderGeneratedResult(data) {
    state.lastGeneratedPassword = data.password;
    elements.generatedPasswordText.textContent = data.password;
    elements.genStatLen.textContent = `${data.length} chars`;
    elements.genStatEntropy.textContent = `${data.entropy_bits} bits`;
    elements.genStatPool.textContent = `${data.pool_size} chars`;

    elements.genRatingBadge.textContent = data.rating.toUpperCase();
    elements.genRatingBadge.className = `cyber-badge badge-${data.rating.toLowerCase().replace(' ', '-')}`;
}

// Client-side fallback generation if server is offline
function clientFallbackGenerate(payload) {
    let charset = '';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    if (payload.use_lower) charset += lower;
    if (payload.use_upper) charset += upper;
    if (payload.use_digits) charset += digits;
    if (payload.use_symbols) charset += symbols;
    if (payload.exclude_ambiguous) {
        charset = charset.replace(/[Il1O0o|]/g, '');
    }
    if (!charset) charset = lower + digits;

    const array = new Uint32Array(payload.length);
    window.crypto.getRandomValues(array);
    let pwd = '';
    for (let i = 0; i < payload.length; i++) {
        pwd += charset[array[i] % charset.length];
    }

    renderGeneratedResult({
        password: pwd,
        length: pwd.length,
        entropy_bits: Math.round(pwd.length * Math.log2(charset.length)),
        pool_size: charset.length,
        rating: pwd.length >= 16 ? 'Very Strong' : 'Strong',
    });
}

// ==========================================================================
// TAB 3: Bulk Auditor
// ==========================================================================
function setupBulkAuditorEvents() {
    elements.runBulkBtn.addEventListener('click', async () => {
        const text = elements.bulkTextarea.value;
        const passwords = text.split('\n').map(p => p.trim()).filter(Boolean);

        if (!passwords.length) {
            showToast('Please enter at least one password to audit', '⚠️');
            return;
        }

        elements.runBulkBtn.textContent = '⏳ Analyzing...';
        elements.runBulkBtn.disabled = true;

        try {
            const res = await fetch('/api/bulk-analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    passwords: passwords,
                    check_breach: elements.bulkHibpToggle.checked,
                }),
            });

            if (res.ok) {
                const data = await res.json();
                renderBulkResults(data);
                showToast(`Audited ${data.summary.total} credentials successfully!`, '🚀');
            } else {
                showToast('Failed to run bulk analysis', '❌');
            }
        } catch (e) {
            showToast('Backend unavailable for bulk audit', '❌');
        } finally {
            elements.runBulkBtn.textContent = '🚀 Run Bulk Audit';
            elements.runBulkBtn.disabled = false;
        }
    });
}

function renderBulkResults(data) {
    const summary = data.summary;
    elements.bulkStatTotal.textContent = summary.total;
    elements.bulkStatAvg.textContent = `${summary.avg_score} / 100`;
    elements.bulkStatCompliant.textContent = `${summary.compliant_count} / ${summary.total}`;
    elements.bulkStatWeak.textContent = summary.weak_count;

    elements.bulkSummaryContainer.style.display = 'grid';
    elements.bulkTableContainer.style.display = 'block';

    elements.bulkTableBody.innerHTML = '';
    data.results.forEach((row, idx) => {
        const tr = document.createElement('tr');
        const ratingClass = `badge-${row.rating.toLowerCase().replace(' ', '-')}`;
        const breachStatus = row.is_breached ? `<span style="color:var(--neon-red); font-weight:bold;">🚨 FOUND (${row.breach_count})</span>` : 'Clean';
        const nistStatus = row.nist_compliant ? '<span style="color:var(--neon-green)">✅ Pass</span>' : '<span style="color:var(--neon-red)">❌ Fail</span>';

        tr.innerHTML = `
            <td>${idx + 1}</td>
            <td style="font-family:var(--font-mono); font-weight:600;">${escapeHtml(row.password)}</td>
            <td><strong>${row.score}</strong> / 100</td>
            <td><span class="cyber-badge ${ratingClass}">${row.rating}</span></td>
            <td>${row.entropy_bits} bits</td>
            <td>${nistStatus}</td>
            <td>${breachStatus}</td>
            <td>${row.vulnerabilities_count} flags</td>
        `;
        elements.bulkTableBody.appendChild(tr);
    });
}

// Start application
document.addEventListener('DOMContentLoaded', initApp);

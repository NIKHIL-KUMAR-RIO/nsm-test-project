// Shield NSM Platform - Threat Rhythm Monitor & SOC Controller (Person 5)

let isLive = true;
let pollTimer = null;
const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
    ? ''
    : 'http://localhost:8080';

// Threat Rhythm State
let attackState = 'normal'; // 'normal' | 'port_scan' | 'syn_flood' | 'brute_force'
let attackStateTimeout = null;
let currentPps = 12;

// Theme configuration
const THEMES = {
    normal: {
        color: '#10b981',
        glow: 'rgba(16, 185, 129, 0.6)',
        fillTop: 'rgba(16, 185, 129, 0.15)',
        badgeClass: 'badge-normal',
        text: 'SYSTEM SECURE • FLATLINE'
    },
    port_scan: {
        color: '#f59e0b',
        glow: 'rgba(245, 158, 11, 0.7)',
        fillTop: 'rgba(245, 158, 11, 0.3)',
        badgeClass: 'badge-portscan',
        text: 'WARNING • PORT SCAN DETECTED'
    },
    syn_flood: {
        color: '#ef4444',
        glow: 'rgba(239, 68, 68, 0.8)',
        fillTop: 'rgba(239, 68, 68, 0.35)',
        badgeClass: 'badge-synflood',
        text: 'CRITICAL • SYN FLOOD ATTACK'
    },
    brute_force: {
        color: '#a855f7',
        glow: 'rgba(168, 85, 247, 0.7)',
        fillTop: 'rgba(168, 85, 247, 0.3)',
        badgeClass: 'badge-bruteforce',
        text: 'ALERT • BRUTE FORCE INTRUSION'
    }
};

// ==========================================
// AUDIO SYNTHESIZER (Web Audio API Alarm)
// ==========================================
let soundEnabled = true;
let audioCtx = null;

function getAudioContext() {
    if (!audioCtx) {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (AudioContextClass) {
            audioCtx = new AudioContextClass();
        }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
        audioCtx.resume();
    }
    return audioCtx;
}

// Unlock audio on first user gesture anywhere on the screen
['click', 'keydown', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, () => {
        getAudioContext();
    }, { once: false });
});

function toggleSound() {
    soundEnabled = !soundEnabled;
    const btn = document.getElementById('btnSoundToggle');
    const txt = document.getElementById('soundStatusText');
    if (soundEnabled) {
        if (btn) btn.className = 'btn btn-sound-on';
        if (txt) txt.textContent = '🔊 Sound: ON';
        playAlertSound(720, 0.08, 'sine');
    } else {
        if (btn) btn.className = 'btn btn-sound-muted';
        if (txt) txt.textContent = '🔇 Sound: OFF';
    }
}

function playAlertSound(freq, duration, type = 'sine') {
    if (!soundEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = type;
        osc.frequency.setValueAtTime(freq, now);

        gain.gain.setValueAtTime(0.18, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + duration);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start(now);
        osc.stop(now + duration);
    } catch (e) {
        console.warn('Audio play error:', e);
    }
}

function playAlertAlarm(severity = 'high') {
    if (!soundEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;

        // Dual-tone urgent security alert siren
        const osc1 = ctx.createOscillator();
        const gain1 = ctx.createGain();
        osc1.type = 'sawtooth';
        osc1.frequency.setValueAtTime(920, now);
        osc1.frequency.exponentialRampToValueAtTime(520, now + 0.14);
        gain1.gain.setValueAtTime(0.2, now);
        gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.14);
        osc1.connect(gain1);
        gain1.connect(ctx.destination);
        osc1.start(now);
        osc1.stop(now + 0.14);

        // Secondary alert echo chirp
        const osc2 = ctx.createOscillator();
        const gain2 = ctx.createGain();
        osc2.type = 'sawtooth';
        osc2.frequency.setValueAtTime(1150, now + 0.16);
        osc2.frequency.exponentialRampToValueAtTime(440, now + 0.32);
        gain2.gain.setValueAtTime(0.22, now + 0.16);
        gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.32);
        osc2.connect(gain2);
        gain2.connect(ctx.destination);
        osc2.start(now + 0.16);
        osc2.stop(now + 0.32);
    } catch (e) {
        console.warn('Alarm audio error:', e);
    }
}

// ==========================================
// CANVAS & ECG WAVEFORM ENGINE
// ==========================================
let canvas, ctx;
const MAX_SAMPLES = 300;
let samples = [];
let rhythmTick = 0;
let animFrameId = null;

document.addEventListener('DOMContentLoaded', () => {
    initEcgCanvas();
    startPolling();
    fetchData();
});

function initEcgCanvas() {
    canvas = document.getElementById('ecgCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Initialize samples buffer with flat baseline
    const baseline = canvas.height * 0.62;
    samples = new Array(MAX_SAMPLES).fill(baseline);

    // Start 60 FPS Continuous Animation Loop
    if (animFrameId) cancelAnimationFrame(animFrameId);
    animFrameId = requestAnimationFrame(renderEcgFrame);
}

function resizeCanvas() {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
}

// 60 FPS Fluid Waveform Generator
function renderEcgFrame() {
    if (!canvas || !ctx) return;

    const width = canvas.getBoundingClientRect().width;
    const height = canvas.getBoundingClientRect().height;
    const baseline = height * 0.62;

    if (isLive) {
        rhythmTick++;

        // Calculate offset based on attack state
        let offset = 0;

        if (attackState === 'normal') {
            // PATIENT DEAD FLATLINE: Perfectly straight, calm horizontal line
            offset = 0;
        } else if (attackState === 'syn_flood') {
            // Violent, high-frequency tachycardia spike storm
            const floodPhase = rhythmTick % 16;
            const chaos = Math.sin(rhythmTick * 0.8) * 25 + Math.cos(rhythmTick * 0.4) * 20;
            if (floodPhase >= 4 && floodPhase < 12) {
                offset = -85 + chaos;
            } else {
                offset = 25 + (Math.random() - 0.5) * 15;
            }
        } else if (attackState === 'port_scan') {
            // Irregular stepped sawtooth scanning bursts
            const scanPhase = rhythmTick % 26;
            const multiPeak = Math.sin(rhythmTick * 0.5) * 35;
            if (scanPhase < 14) {
                offset = -55 + multiPeak;
            } else {
                offset = 10 + (Math.random() - 0.5) * 10;
            }
        } else if (attackState === 'brute_force') {
            // Periodic sharp needle bursts
            const brutePhase = rhythmTick % 22;
            if (brutePhase >= 7 && brutePhase < 12) {
                offset = -60 * Math.sin(((brutePhase - 7) / 5) * Math.PI);
            } else if (brutePhase >= 12 && brutePhase < 14) {
                offset = 12;
            }
        }

        // Push new sample and roll left (fluid continuous motion)
        samples.shift();
        samples.push(baseline + offset);
    }

    // --- DRAWING ---
    ctx.clearRect(0, 0, width, height);

    // 1. Draw Oscilloscope Grid
    drawCyberGrid(ctx, width, height, baseline);

    // 2. Select Theme Colors
    const theme = THEMES[attackState] || THEMES.normal;

    // 3. Draw Area Fill Under Curve
    const stepX = width / (MAX_SAMPLES - 1);
    ctx.beginPath();
    ctx.moveTo(0, height);
    for (let i = 0; i < MAX_SAMPLES; i++) {
        ctx.lineTo(i * stepX, samples[i]);
    }
    ctx.lineTo(width, height);
    ctx.closePath();

    const fillGrad = ctx.createLinearGradient(0, 0, 0, height);
    fillGrad.addColorStop(0, theme.fillTop);
    fillGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
    ctx.fillStyle = fillGrad;
    ctx.fill();

    // 4. Draw Glowing Waveform Line
    ctx.beginPath();
    ctx.moveTo(0, samples[0]);
    for (let i = 1; i < MAX_SAMPLES; i++) {
        ctx.lineTo(i * stepX, samples[i]);
    }
    ctx.strokeStyle = theme.color;
    ctx.lineWidth = 2.5;
    ctx.shadowColor = theme.glow;
    ctx.shadowBlur = 14;
    ctx.stroke();

    // Reset shadow
    ctx.shadowBlur = 0;

    // 5. Draw Glowing Leading Tracer Dot (Right Edge)
    const headX = (MAX_SAMPLES - 1) * stepX;
    const headY = samples[MAX_SAMPLES - 1];

    ctx.beginPath();
    ctx.arc(headX, headY, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.shadowColor = theme.color;
    ctx.shadowBlur = 16;
    ctx.fill();

    ctx.beginPath();
    ctx.arc(headX, headY, 8, 0, Math.PI * 2);
    ctx.strokeStyle = theme.color;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.shadowBlur = 0;

    // Continue 60 FPS Loop
    animFrameId = requestAnimationFrame(renderEcgFrame);
}

function drawCyberGrid(ctx, w, h, baseline) {
    ctx.save();
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;

    // Vertical grid lines
    const gridSpacing = 40;
    for (let x = 0; x < w; x += gridSpacing) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
    }

    // Horizontal grid lines
    for (let y = 0; y < h; y += gridSpacing) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    // Baseline reference (subtle dotted line)
    ctx.strokeStyle = 'rgba(16, 185, 129, 0.12)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, baseline);
    ctx.lineTo(w, baseline);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.restore();
}

// State Management & Theme Transition
function setAttackState(state) {
    attackState = state;
    const theme = THEMES[state] || THEMES.normal;

    const badge = document.getElementById('rhythmBadge');
    const badgeText = document.getElementById('rhythmText');
    const rhythmCard = document.getElementById('rhythmCard');

    if (badge && badgeText) {
        badge.className = `rhythm-badge ${theme.badgeClass}`;
        badgeText.textContent = theme.text;
    }

    if (rhythmCard) {
        if (state === 'normal') {
            rhythmCard.style.boxShadow = 'none';
        } else {
            rhythmCard.style.boxShadow = `0 0 20px ${theme.fillTop}`;
        }
    }

    // Reset decay timer: return to flatline after 7 seconds if no new alerts arrive
    if (attackStateTimeout) clearTimeout(attackStateTimeout);
    if (state !== 'normal') {
        attackStateTimeout = setTimeout(() => {
            setAttackState('normal');
        }, 7000);
    }
}

// ==========================================
// POLLING & DATA RETRIEVAL
// ==========================================
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
        if (isLive) {
            fetchData();
        }
    }, 1500); // 1.5s background polling
}

function toggleLiveState() {
    isLive = !isLive;
    const btn = document.getElementById('btnLiveToggle');
    const txt = document.getElementById('liveStatusText');

    if (isLive) {
        btn.className = 'btn btn-live';
        txt.textContent = 'LIVE (Real-Time)';
        fetchData();
    } else {
        btn.className = 'btn btn-paused';
        txt.textContent = 'PAUSED';
    }
}

async function fetchData() {
    try {
        await Promise.all([
            fetchTrafficStats(),
            fetchAlerts(),
            fetchSummary(),
            fetchTopIps()
        ]);
    } catch (err) {
        console.error('Error polling NSM API:', err);
    }
}

async function fetchTrafficStats() {
    try {
        const res = await fetch(`${API_BASE}/api/traffic-stats`);
        if (!res.ok) return;
        const data = await res.json();

        if (data.packets_per_sec && data.packets_per_sec.length > 0) {
            currentPps = data.packets_per_sec[data.packets_per_sec.length - 1];
            const rateElem = document.getElementById('rhythmRate');
            if (rateElem && rateElem.textContent !== String(currentPps)) {
                rateElem.textContent = currentPps;
            }
        }
    } catch (e) {}
}

// Fingerprints to avoid unnecessary DOM rerenders (eliminates blipping/flashing)
let lastAlertsFingerprint = '';
let lastTopIpsFingerprint = '';
let lastSummaryJson = '';

async function fetchAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=50`);
        if (!res.ok) return;
        const alerts = await res.json();
        renderAlerts(alerts);

        // Check newest alert to dynamically update ECG threat state
        if (alerts && alerts.length > 0) {
            const newest = alerts[0];
            const alertTime = new Date(newest.timestamp).getTime();
            const now = Date.now();

            // If alert occurred within the last 8 seconds, morph waveform into attack state
            if (now - alertTime < 8000) {
                if (newest.attack_type === 'syn_flood') {
                    setAttackState('syn_flood');
                } else if (newest.attack_type === 'port_scan') {
                    setAttackState('port_scan');
                } else if (newest.attack_type === 'brute_force') {
                    setAttackState('brute_force');
                }
            }
        }
    } catch (e) {}
}

async function fetchSummary() {
    try {
        const res = await fetch(`${API_BASE}/api/summary`);
        if (!res.ok) return;
        const sum = await res.json();
        const json = JSON.stringify(sum);

        if (json === lastSummaryJson) return; // Do not touch DOM if values haven't changed
        lastSummaryJson = json;

        const elPort = document.getElementById('sumPortScan');
        const elBrute = document.getElementById('sumBruteForce');
        const elSyn = document.getElementById('sumSynFlood');
        if (elPort) elPort.textContent = sum.port_scan || 0;
        if (elBrute) elBrute.textContent = sum.brute_force || 0;
        if (elSyn) elSyn.textContent = sum.syn_flood || 0;
    } catch (e) {}
}

async function fetchTopIps() {
    try {
        const res = await fetch(`${API_BASE}/api/top-ips?limit=5`);
        if (!res.ok) return;
        const topIps = await res.json();
        renderTopIps(topIps);
    } catch (e) {}
}

// ==========================================
// RENDER ALERTS FEED & TOP IPS (STABLE & STILL)
// ==========================================
function renderAlerts(alerts) {
    const count = alerts ? alerts.length : 0;
    const countElem = document.getElementById('activeAlertsCount');
    if (countElem && countElem.textContent !== String(count)) {
        countElem.textContent = count;
    }

    if (!alerts || alerts.length === 0) {
        if (lastAlertsFingerprint !== 'EMPTY') {
            lastAlertsFingerprint = 'EMPTY';
            const container = document.getElementById('alertsContainer');
            if (container) {
                container.innerHTML = `
                    <div style="text-align: center; color: var(--text-muted); padding: 3rem 0; font-size: 0.85rem;">
                        🛡️ No security alerts detected yet. Listening for traffic...
                    </div>`;
            }
        }
        return;
    }

    // Fingerprint: alert ID list + count
    const currentFingerprint = alerts.map(a => a.alert_id).join(',');

    // CRITICAL FIX: If fingerprint matches, DO NOT touch innerHTML!
    // This stops the 0.1s/1.5s blipping/flickering completely!
    if (currentFingerprint === lastAlertsFingerprint) {
        return;
    }

    // If new alerts have arrived, trigger alarm sound
    if (lastAlertsFingerprint !== '' && lastAlertsFingerprint !== 'EMPTY') {
        const prevList = lastAlertsFingerprint.split(',');
        const hasBrandNew = alerts.some(a => !prevList.includes(a.alert_id));
        if (hasBrandNew) {
            playAlertAlarm(alerts[0].severity);
        }
    }

    lastAlertsFingerprint = currentFingerprint;
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    container.innerHTML = alerts.map(a => {
        const timeFormatted = new Date(a.timestamp).toLocaleTimeString();
        const methodTag = a.detection_method === 'ml'
            ? `<span class="badge badge-method-ml">🧠 ML MODEL</span>`
            : `<span class="badge badge-method-rule">⚙️ RULE</span>`;

        return `
            <div class="alert-card severity-${a.severity}">
                <div class="alert-card-header">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="badge badge-${a.severity}">[${a.severity.toUpperCase()}]</span>
                        <strong style="color: #fff; font-size: 0.82rem;">${a.attack_type.replace('_', ' ').toUpperCase()}</strong>
                        ${methodTag}
                    </div>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${timeFormatted}</span>
                </div>
                <div class="alert-desc">${a.details || 'Suspicious network behavior identified.'}</div>
                <div class="alert-meta">
                    <span>Source: <strong style="color: #e2e8f0;">${a.src_ip}</strong></span>
                    <span>Target: <strong style="color: #e2e8f0;">${a.dst_ip}</strong></span>
                    <span>Confidence: <strong style="color: #38bdf8;">${Math.round(a.confidence * 100)}%</strong></span>
                </div>
            </div>`;
    }).join('');
}

function renderTopIps(topIps) {
    const fingerprint = JSON.stringify(topIps || []);
    if (fingerprint === lastTopIpsFingerprint) return; // Do not touch DOM if identical
    lastTopIpsFingerprint = fingerprint;

    const tbody = document.getElementById('topIpsTableBody');
    if (!tbody) return;

    if (!topIps || topIps.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">No attacking hosts detected yet</td></tr>`;
        return;
    }

    tbody.innerHTML = topIps.map(ip => `
        <tr>
            <td style="color: #f87171; font-weight: 600;">${ip.src_ip}</td>
            <td><strong style="color: #fff;">${ip.alert_count}</strong></td>
            <td style="color: var(--text-muted);">${new Date(ip.last_seen).toLocaleTimeString()}</td>
        </tr>
    `).join('');
}

// ==========================================
// ATTACK TRIGGERS & CLEAR ACTIONS
// ==========================================
async function triggerAttack(type) {
    playAlertAlarm('high');

    // Immediately morph the ECG waveform and badge into attack state
    if (type === 'port-scan') setAttackState('port_scan');
    else if (type === 'syn-flood') setAttackState('syn_flood');
    else if (type === 'brute-force') setAttackState('brute_force');

    try {
        await fetch(`${API_BASE}/api/attack/${type}`, { method: 'POST' });
        setTimeout(fetchData, 400);
    } catch (err) {
        console.error(`Failed to trigger ${type}:`, err);
    }
}

async function handlePcapUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    setAttackState('port_scan');
    playAlertAlarm('medium');

    const formData = new FormData();
    formData.append('file', file);

    try {
        await fetch(`${API_BASE}/api/upload-pcap`, { method: 'POST', body: formData });
        setTimeout(fetchData, 500);
    } catch (err) {
        console.error('Error uploading PCAP:', err);
    }
}

async function clearAlerts() {
    // 1. Immediately return waveform to flatline
    setAttackState('normal');

    // 2. Wipe local UI immediately (instant responsiveness)
    lastAlertsFingerprint = 'EMPTY';
    lastTopIpsFingerprint = 'EMPTY';
    lastSummaryJson = '';

    renderAlerts([]);
    renderTopIps([]);

    const elPort = document.getElementById('sumPortScan');
    const elBrute = document.getElementById('sumBruteForce');
    const elSyn = document.getElementById('sumSynFlood');
    const elActive = document.getElementById('activeAlertsCount');
    if (elPort) elPort.textContent = '0';
    if (elBrute) elBrute.textContent = '0';
    if (elSyn) elSyn.textContent = '0';
    if (elActive) elActive.textContent = '0';

    // 3. Clear backend storage and reset detection engines
    try {
        const res = await fetch(`${API_BASE}/api/alerts/clear`, { method: 'POST' });
        if (!res.ok) {
            await fetch(`${API_BASE}/api/alerts`, { method: 'DELETE' });
        }
    } catch (err) {
        try {
            await fetch(`${API_BASE}/api/alerts`, { method: 'DELETE' });
        } catch (e2) {
            console.error('Error clearing alerts:', e2);
        }
    }

    // 4. Re-sync with backend
    setTimeout(fetchData, 300);
}

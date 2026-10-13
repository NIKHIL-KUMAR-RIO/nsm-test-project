// ==========================================================================
// NETSENTINEL ENTERPRISE PLATFORM CONTROLLER (PERSON 4 & PERSON 5)
// Supports Multi-Language (EN/ES/DE/FR), Dual-Theme, Multi-View SPA & Telemetry
// ==========================================================================

let isLive = true;
let pollTimer = null;
const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
    ? ''
    : 'http://localhost:8080';

// Threat Rhythm State
let attackState = 'normal'; // 'normal' | 'port_scan' | 'syn_flood' | 'brute_force'
let attackStateTimeout = null;
let currentPps = 12;

// ==========================================
// TIER 1 SECURITY HARDENING: XSS ESCAPING
// ==========================================
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ==========================================
// TIER 2 SECURITY HARDENING: AUTH & RBAC CONTEXT
// ==========================================
let currentUser = null;

async function fetchCurrentUser() {
    try {
        const res = await fetch(`${API_BASE}/api/auth/me`, { cache: 'no-store', credentials: 'include' });
        if (res.status === 401 || res.status === 403) {
            if (window.location.protocol !== 'file:') {
                window.location.href = '/login.html';
                return;
            }
        }
        if (res.ok) {
            currentUser = await res.json();
            try { localStorage.setItem('netsentinel_user', JSON.stringify(currentUser)); } catch (_) {}
            renderUserBadge(currentUser);
            return;
        }
    } catch (e) {
        console.warn('Auth status check error:', e);
    }

    if (window.location.protocol === 'file:') {
        currentUser = { username: 'operator', isAdmin: false, roles: ['ROLE_ANALYST'] };
        renderUserBadge(currentUser);
    } else {
        window.location.href = '/login.html';
    }
}

function handleLogout() {
    try { localStorage.removeItem('netsentinel_user'); } catch (_) {}
    if (window.location.protocol === 'file:') {
        window.location.href = 'login.html?logout=true';
    } else {
        window.location.href = '/logout';
    }
}

function renderUserBadge(user) {
    if (!user) return;
    const usernameEl = document.getElementById('usernameDisplay');
    const roleEl = document.getElementById('roleDisplay');
    const roleIcon = document.getElementById('userRoleIcon');
    const brandLabel = document.getElementById('brandConsoleLabel');
    const btnUserMgmt = document.getElementById('btnUserManagement');
    const pendingPill = document.getElementById('pendingBadgePill');
    const btnClearAlerts = document.getElementById('btnClearAlerts');
    const adminSimBar = document.getElementById('adminSimBar');

    if (usernameEl) {
        usernameEl.textContent = user.username || 'operator';
        if (user.fullName) {
            usernameEl.title = `${user.fullName} (${user.email || user.username})`;
        }
    }
    if (roleEl) {
        roleEl.style.display = 'inline-block';
    }

    if (user.isAdmin) {
        if (roleIcon) roleIcon.textContent = '👑';
        if (roleEl) {
            roleEl.textContent = '👑 SOC ADMIN';
            roleEl.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
            roleEl.style.color = '#f87171';
            roleEl.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        }
        if (brandLabel) {
            brandLabel.textContent = 'SOC ADMIN';
            brandLabel.style.color = 'var(--accent-red)';
        }
        if (adminSimBar) {
            adminSimBar.style.display = 'block';
        }
        const userMgmtWrapper = document.getElementById('userMgmtWrapper');
        if (userMgmtWrapper) userMgmtWrapper.style.display = 'inline-block';
        if (btnUserMgmt) {
            btnUserMgmt.style.display = 'inline-flex';
            const count = user.pendingCount || 0;
            if (count > 0) {
                if (pendingPill) {
                    pendingPill.style.display = 'inline-block';
                    pendingPill.textContent = count;
                }
                btnUserMgmt.title = `${count} pending operator registration request(s) - Hover or Click to approve`;
            } else {
                if (pendingPill) pendingPill.style.display = 'none';
                btnUserMgmt.title = 'Manage SOC Operator Accounts (Admin Console)';
            }
        }
        updateHoverPendingList();
        if (btnClearAlerts) {
            btnClearAlerts.style.display = 'inline-flex';
        }
    } else {
        // ANALYST Role
        if (roleIcon) roleIcon.textContent = '🛡️';
        if (roleEl) {
            roleEl.textContent = '🛡️ ANALYST';
            roleEl.style.backgroundColor = 'rgba(56, 189, 248, 0.2)';
            roleEl.style.color = '#38bdf8';
            roleEl.style.border = '1px solid rgba(56, 189, 248, 0.4)';
        }
        if (brandLabel) {
            brandLabel.textContent = 'SOC ANALYST';
            brandLabel.style.color = 'var(--accent-blue)';
        }
        if (adminSimBar) {
            adminSimBar.style.display = 'none';
        }
        const userMgmtWrapper = document.getElementById('userMgmtWrapper');
        if (userMgmtWrapper) userMgmtWrapper.style.display = 'none';
        if (btnUserMgmt) {
            btnUserMgmt.style.display = 'none';
        }
        if (btnClearAlerts) {
            btnClearAlerts.style.display = 'none'; // Analyst cannot clear alerts
        }
    }
}

// ==========================================
// USER MANAGEMENT MODAL & DROPDOWN CONTROLS (OPTION A)
// ==========================================
function openUserManagementModal() {
    const modal = document.getElementById('userManagementModal');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('active');
        loadUserManagementList();
    }
}

function closeUserManagementModal() {
    const modal = document.getElementById('userManagementModal');
    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('active');
    }
}

async function updateHoverPendingList(cachedUsers, cachedPending) {
    const hoverList = document.getElementById('userMgmtHoverList');
    const hoverBadge = document.getElementById('hoverPendingCountBadge');
    if (!hoverList) return;

    try {
        let users = cachedUsers;
        let pending = cachedPending;

        if (!users) {
            const res = await fetch(`${API_BASE}/api/admin/users`, { credentials: 'include' });
            if (!res.ok) return;
            const data = await res.json();
            users = data.users || [];
            pending = data.pending !== undefined ? data.pending : 0;
        }

        const pendingUsers = users.filter(u => u.accountStatus === 'PENDING');

        if (hoverBadge) {
            if (pendingUsers.length > 0) {
                hoverBadge.textContent = `${pendingUsers.length} PENDING`;
                hoverBadge.style.display = 'inline-block';
                hoverBadge.style.background = '#f59e0b';
                hoverBadge.style.color = '#000';
            } else {
                hoverBadge.textContent = '0 PENDING';
                hoverBadge.style.background = 'rgba(148, 163, 184, 0.25)';
                hoverBadge.style.color = 'var(--text-muted)';
            }
        }

        if (pendingUsers.length === 0) {
            hoverList.innerHTML = `
                <div style="padding: 1rem 0.5rem; text-align: center; color: var(--text-muted); font-size: 0.78rem;">
                    ✓ No pending access requests.<br>All operator accounts are active.
                </div>
            `;
            return;
        }

        hoverList.innerHTML = pendingUsers.map(u => `
            <div style="padding: 0.6rem; margin-bottom: 0.4rem; background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 6px;">
                    <div>
                        <div style="font-weight: 700; color: var(--text-primary); font-size: 0.82rem;">${escapeHtml(u.fullName || u.username)}</div>
                        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--accent-blue);">${escapeHtml(u.username)}</div>
                        <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(u.email || '')}</div>
                    </div>
                    <span style="background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.4); padding: 1px 6px; border-radius: 4px; font-weight: 700; font-size: 0.65rem; white-space: nowrap;">⏳ PENDING</span>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 6px; margin-top: 0.45rem; padding-top: 0.35rem; border-top: 1px dashed rgba(148, 163, 184, 0.15);">
                    <button class="btn btn-sm" onclick="approveUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="background: #059669; border-color: #047857; color: #fff; padding: 3px 10px; font-size: 0.72rem; font-weight: 700;" title="Approve registration">
                        ✓ Approve
                    </button>
                    <button class="btn btn-sm" onclick="deleteUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="border-color: #ef4444; color: #f87171; padding: 3px 7px; font-size: 0.72rem;" title="Reject registration">
                        ✕
                    </button>
                </div>
            </div>
        `).join('');
    } catch (_) {}
}

async function loadUserManagementList() {
    const tbody = document.getElementById('userTableBody');
    const summaryEl = document.getElementById('userMgmtSummaryText');
    const pendingPill = document.getElementById('pendingBadgePill');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="6" style="padding: 18px; text-align: center; color: var(--text-muted);">Fetching operator records...</td></tr>';

    try {
        const res = await fetch(`${API_BASE}/api/admin/users`, { credentials: 'include' });
        if (res.status === 403) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding: 18px; text-align: center; color: #f87171;">Access Denied: Only SOC Administrators can manage accounts.</td></tr>';
            return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);

        const data = await res.json();
        const users = data.users || [];
        const pending = data.pending || 0;

        if (summaryEl) {
            summaryEl.innerHTML = `Total Operators: <strong>${users.length}</strong> &nbsp;|&nbsp; Pending Approval: <strong style="color: #f59e0b;">${pending}</strong>`;
        }
        if (pendingPill) {
            if (pending > 0) {
                pendingPill.style.display = 'inline-block';
                pendingPill.textContent = pending;
            } else {
                pendingPill.style.display = 'none';
            }
        }

        updateHoverPendingList(users, pending);

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding: 18px; text-align: center; color: var(--text-muted);">No operator accounts found.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => {
            const isSelf = currentUser && (currentUser.username === u.username || currentUser.email === u.email);
            
            let statusBadge = '';
            if (u.accountStatus === 'ACTIVE') {
                statusBadge = '<span style="background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem;">ACTIVE</span>';
            } else if (u.accountStatus === 'PENDING') {
                statusBadge = '<span style="background: rgba(245, 158, 11, 0.15); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.35); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem;">⏳ PENDING</span>';
            } else {
                statusBadge = '<span style="background: rgba(244, 63, 94, 0.15); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.35); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 0.72rem;">DISABLED</span>';
            }

            let roleBadge = u.role === 'ADMIN'
                ? '<span style="color: #f87171; font-weight: 700; font-size: 0.75rem;">👑 ADMIN</span>'
                : '<span style="color: #38bdf8; font-weight: 700; font-size: 0.75rem;">🛡️ ANALYST</span>';

            let actionButtons = '<div style="display: flex; gap: 4px; justify-content: flex-end;">';
            if (u.accountStatus === 'PENDING') {
                actionButtons += `<button class="btn btn-sm" onclick="approveUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="background: #059669; border-color: #047857; color: #fff; padding: 3px 8px; font-size: 0.72rem;" title="Approve registration">✓ Approve</button>`;
            } else if (u.accountStatus === 'ACTIVE' && !isSelf) {
                actionButtons += `<button class="btn btn-sm" onclick="disableUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="border-color: #f59e0b; color: #fbbf24; padding: 3px 8px; font-size: 0.72rem;" title="Deactivate user">Disable</button>`;
            } else if (u.accountStatus === 'DISABLED' && !isSelf) {
                actionButtons += `<button class="btn btn-sm" onclick="approveUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="border-color: #10b981; color: #6ee7b7; padding: 3px 8px; font-size: 0.72rem;" title="Reactivate user">Reactivate</button>`;
            }
            if (!isSelf) {
                actionButtons += `<button class="btn btn-sm" onclick="deleteUserAccount(${u.id}, '${escapeHtml(u.username)}')" style="border-color: #ef4444; color: #f87171; padding: 3px 7px; font-size: 0.72rem;" title="Delete user">✕</button>`;
            } else {
                actionButtons += '<span style="color: var(--text-muted); font-size: 0.72rem; padding: 3px 6px;">(You)</span>';
            }
            actionButtons += '</div>';

            return `
                <tr style="border-bottom: 1px solid var(--card-border-subtle);">
                    <td style="padding: 10px 12px; font-weight: 600;">${escapeHtml(u.fullName || u.username)}</td>
                    <td style="padding: 10px 12px;">
                        <span style="font-family: var(--font-mono); color: var(--text-primary);">${escapeHtml(u.username)}</span><br>
                        <small style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(u.email || '')}</small>
                    </td>
                    <td style="padding: 10px 12px;">${roleBadge}</td>
                    <td style="padding: 10px 12px;">${statusBadge}</td>
                    <td style="padding: 10px 12px; font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(u.lastLogin && u.lastLogin !== 'null' ? u.lastLogin.substring(0, 19).replace('T', ' ') : 'Never')}</td>
                    <td style="padding: 10px 12px; text-align: right;">${actionButtons}</td>
                </tr>
            `;
        }).join('');

    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="padding: 18px; text-align: center; color: #f87171;">Failed to load operators: ${err.message}</td></tr>`;
    }
}

async function approveUserAccount(id, username) {
    try {
        const res = await fetch(`${API_BASE}/api/admin/users/${id}/approve`, {
            method: 'POST',
            credentials: 'include'
        });
        if (res.ok) {
            loadUserManagementList();
            fetchCurrentUser();
        } else {
            const err = await res.json();
            alert('Approval error: ' + (err.message || res.statusText));
        }
    } catch (e) {
        alert('Network error approving operator: ' + e.message);
    }
}

async function disableUserAccount(id, username) {
    if (!confirm(`Are you sure you want to deactivate operator "${username}"?`)) return;
    try {
        const res = await fetch(`${API_BASE}/api/admin/users/${id}/disable`, {
            method: 'POST',
            credentials: 'include'
        });
        if (res.ok) {
            loadUserManagementList();
        } else {
            const err = await res.json();
            alert('Error: ' + (err.message || res.statusText));
        }
    } catch (e) {
        alert('Network error: ' + e.message);
    }
}

async function deleteUserAccount(id, username) {
    if (!confirm(`Permanently delete account for "${username}"? This cannot be undone.`)) return;
    try {
        const res = await fetch(`${API_BASE}/api/admin/users/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        if (res.ok) {
            loadUserManagementList();
            fetchCurrentUser();
        } else {
            const err = await res.json();
            alert('Error: ' + (err.message || res.statusText));
        }
    } catch (e) {
        alert('Network error: ' + e.message);
    }
}

// ==========================================
// DUAL-THEME SWITCHER (DARK / LIGHT)
// ==========================================
function initTheme() {
    const savedTheme = localStorage.getItem('nsm_theme') || 'dark';
    applyTheme(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(newTheme);
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('nsm_theme', theme);
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
    // Re-draw canvas baseline for theme contrast
    if (canvas) {
        resizeCanvas();
    }
}

// ==========================================
// MULTI-LANGUAGE SYSTEM (EN, ES, DE, FR)
// ==========================================
const i18n = {
    en: {
        nav_dashboards: 'MY DASHBOARDS',
        nav_sec_ops: 'SECURITY OPERATIONS',
        menu_live_soc: 'Live SOC Threat Rhythm',
        menu_vuln_risk: 'Vulnerability & Risk Dashboard',
        menu_nodes: 'Node & Host Inventory',
        menu_threat_map: 'Global Threat Map & WAN',
        menu_signatures: 'Threat Signature Registry',
        nav_knowledge: 'KNOWLEDGE & ARCHITECTURE',
        menu_capabilities_faq: 'Capabilities & Knowledge Base',
        nav_alerts: 'ALERTS & ACTIVITY',
        menu_active_stream: 'Real-Time Alert Stream',
        menu_attack_vectors: 'Threat Signatures & Attack Vectors',
        nav_resources: 'RESOURCES',
        menu_faq: 'SolarWinds-Style FAQ',
        menu_capabilities: 'Zeek Core Capabilities',
        live_status: 'LIVE',
        btn_clear: 'Clear',
        btn_logout: 'Logout',
        sim_bar_title: '⚡ Interactive Attack Triggers (Demo Helper)',
        sim_port_scan: 'Port Scan',
        sim_syn_flood: 'SYN Flood',
        sim_brute_force: 'Brute Force (SSH)',
        sim_pcap_replay: 'Replay .pcap',
        title_live_rhythm: 'Live Threat Rhythm Monitor',
        title_threat_breakdown: 'Incident Telemetry',
        stat_active_alerts: 'Active Alerts',
        stat_port_scans: 'Port Scans',
        stat_syn_floods: 'SYN Floods',
        stat_brute_force: 'Brute Force',
        title_recent_alerts: 'Recent Security Alerts',
        title_top_ips: 'Top Attacking Hosts',
        card_node_count: 'Node Count by Vulnerability',
        tile_monitored_nodes: 'Monitored',
        tile_critical: 'Critical',
        tile_high: 'High',
        tile_medium: 'Medium',
        card_vuln_count: 'Threat Count by Severity',
        card_risk_score: 'Combined Risk Score',
        gauge_caption: 'Weighted arithmetic mean of host vulnerability scores. Weights: Critical=5, High=3, Medium=1, Low=0.5',
        title_detailed_forensics: 'Live Threat & Vulnerability Forensics',
        title_top_vulns: 'Top Detected Vulnerabilities & CVEs',
        title_dist_chart: 'Threat Distribution by Infrastructure OS',
        filter_health: 'Health',
        filter_tracked: 'Tracked In',
        filter_os: 'OS / Device Family',
        title_node_inventory: 'List of Monitored Nodes',
        title_sig_registry: 'Known Network Signatures & Threat Catalog',
        title_threat_map: 'Interactive Worldwide Threat Map',
        title_wan_traffic: 'WAN Traffic Errors & Discard Telemetry',
        title_sensor_health: 'Hardware & Sensor Health Status',
        cap_badge: 'PLATFORM CAPABILITIES',
        cap_title: 'Deep Network Security Insight',
        cap_subtitle: 'NetSentinel provides multi-layered packet inspection, signature detection, and anomaly detection across network infrastructure.',
        cap_protocol_title: 'Protocol Analysis',
        cap_protocol_desc: 'Deep inspection of packet headers and transport layer sessions including TCP SYN/ACK flags, UDP datagrams, ICMP echo requests, and port multiplexing.',
        cap_threat_title: 'Threat Detection',
        cap_threat_desc: 'Rapid correlation of attack patterns including multi-port reconnaissance sweeps, volumetric SYN flood denial-of-service, and credential brute force attempts.',
        cap_logging_title: 'Comprehensive Logging',
        cap_logging_desc: 'Structured persistence in SQLite with Write-Ahead Logging (WAL) mode, maintaining complete forensics logs ready for SIEM reporting and timeline playback.',
        cap_engine_title: 'Dual-Engine Architecture',
        cap_engine_desc: 'Combines deterministic Snort-like signature matching (Person 2) with statistical anomaly thresholds (Person 3) for robust threat identification.',
        cap_perf_title: 'High Performance',
        cap_perf_desc: 'Engineered on Java 21 Project Loom virtual threads, allowing lightweight decoy honeypot listeners on ports 2222, 8088, 8888, and 9090 without thread starvation.',
        cap_vis_title: 'Network Visibility',
        cap_vis_desc: 'Live real-time SOC monitoring with heart-rate threat rhythm waveforms, continuous risk gauges, and interactive host popovers for immediate situational awareness.'
    },
    es: {
        nav_dashboards: 'MIS PANELES',
        nav_sec_ops: 'OPERACIONES DE SEGURIDAD',
        menu_live_soc: 'Ritmo de Amenazas SOC en Vivo',
        menu_vuln_risk: 'Panel de Vulnerabilidades y Riesgo',
        menu_nodes: 'Inventario de Nodos y Hosts',
        menu_threat_map: 'Mapa Global de Amenazas y WAN',
        menu_signatures: 'Registro de Firmas de Amenazas',
        nav_knowledge: 'CONOCIMIENTO Y ARQUITECTURA',
        menu_capabilities_faq: 'Capacidades y Base de Conocimientos',
        nav_alerts: 'ALERTAS Y ACTIVIDAD',
        menu_active_stream: 'Transmisión de Alertas en Tiempo Real',
        menu_attack_vectors: 'Firmas de Amenazas y Vectores de Ataque',
        nav_resources: 'RECURSOS',
        menu_faq: 'Preguntas Frecuentes',
        menu_capabilities: 'Capacidades Centrales de Zeek',
        live_status: 'EN VIVO',
        btn_clear: 'Limpiar',
        btn_logout: 'Cerrar Sesión',
        sim_bar_title: '⚡ Disparadores de Ataque Interactivos',
        sim_port_scan: 'Escaneo de Puertos',
        sim_syn_flood: 'Inundación SYN',
        sim_brute_force: 'Fuerza Bruta (SSH)',
        sim_pcap_replay: 'Reproducir .pcap',
        title_live_rhythm: 'Monitor de Ritmo de Amenazas en Vivo',
        title_threat_breakdown: 'Telemetría de Incidentes',
        stat_active_alerts: 'Alertas Activas',
        stat_port_scans: 'Escaneos de Puerto',
        stat_syn_floods: 'Inundaciones SYN',
        stat_brute_force: 'Fuerza Bruta',
        title_recent_alerts: 'Alertas de Seguridad Recientes',
        title_top_ips: 'Principales Hosts Atacantes',
        card_node_count: 'Conteo de Nodos por Vulnerabilidad',
        tile_monitored_nodes: 'Monitoreados',
        tile_critical: 'Crítico',
        tile_high: 'Alto',
        tile_medium: 'Medio',
        card_vuln_count: 'Conteo de Amenazas por Gravedad',
        card_risk_score: 'Puntuación de Riesgo Combinada',
        gauge_caption: 'Media aritmética ponderada de puntuaciones de vulnerabilidad de hosts.',
        title_detailed_forensics: 'Telemetría Forense de Amenazas y Vulnerabilidades',
        title_top_vulns: 'Principales Vulnerabilidades Detectadas y CVEs',
        title_dist_chart: 'Distribución de Amenazas por SO de Infraestructura',
        filter_health: 'Estado de Salud',
        filter_tracked: 'Rastreado En',
        filter_os: 'Familia de SO / Dispositivo',
        title_node_inventory: 'Lista de Nodos Monitoreados',
        title_sig_registry: 'Catálogo de Firmas de Red Conocidas',
        title_threat_map: 'Mapa Mundial Interactivo de Amenazas',
        title_wan_traffic: 'Telemetría de Errores y Descartes WAN',
        title_sensor_health: 'Estado de Salud de Hardware y Sensores',
        cap_badge: 'CAPACIDADES DE LA PLATAFORMA',
        cap_title: 'Información Profunda de Seguridad de Red',
        cap_subtitle: 'NetSentinel proporciona inspección de paquetes multicapa y detección de anomalías.',
        cap_protocol_title: 'Análisis de Protocolos',
        cap_protocol_desc: 'Inspección profunda de encabezados de paquetes y sesiones de capa de transporte TCP/UDP.',
        cap_threat_title: 'Detección de Amenazas',
        cap_threat_desc: 'Correlación rápida de patrones de ataque incluyendo barridos de puertos y ataques DoS.',
        cap_logging_title: 'Registro Completo',
        cap_logging_desc: 'Persistencia estructurada en SQLite con modo WAL para análisis forense SIEM.',
        cap_engine_title: 'Arquitectura de Doble Motor',
        cap_engine_desc: 'Combina coincidencia de firmas con umbrales estadísticos de anomalías de ML.',
        cap_perf_title: 'Alto Rendimiento',
        cap_perf_desc: 'Desarrollado sobre hilos virtuales Java 21 Project Loom para alta concurrencia.',
        cap_vis_title: 'Visibilidad de Red',
        cap_vis_desc: 'Monitoreo en tiempo real de operaciones de seguridad con ondas de ritmo de amenaza.'
    },
    de: {
        nav_dashboards: 'MEINE DASHBOARDS',
        nav_sec_ops: 'SICHERHEITSOPERATIONEN',
        menu_live_soc: 'Live-SOC-Bedrohungsrhythmus',
        menu_vuln_risk: 'Schwachstellen- & Risiko-Dashboard',
        menu_nodes: 'Knoten- & Host-Inventar',
        menu_threat_map: 'Globale Bedrohungskarte & WAN',
        menu_signatures: 'Bedrohungssignaturen-Register',
        nav_knowledge: 'WISSEN & ARCHITEKTUR',
        menu_capabilities_faq: 'Fähigkeiten & Wissensdatenbank',
        nav_alerts: 'ALARME & AKTIVITÄT',
        menu_active_stream: 'Echtzeit-Alarmstream',
        menu_attack_vectors: 'Bedrohungssignaturen & Angriffsvektoren',
        nav_resources: 'RESSOURCEN',
        menu_faq: 'FAQ im SolarWinds-Stil',
        menu_capabilities: 'Zeek-Kernfunktionen',
        live_status: 'LIVE',
        btn_clear: 'Bereinigen',
        btn_logout: 'Abmelden',
        sim_bar_title: '⚡ Interaktive Angriffsauslöser',
        sim_port_scan: 'Port-Scan',
        sim_syn_flood: 'SYN-Flood',
        sim_brute_force: 'Brute-Force (SSH)',
        sim_pcap_replay: '.pcap wiederholen',
        title_live_rhythm: 'Live-Bedrohungsrhythmus-Monitor',
        title_threat_breakdown: 'Vorfallstelemetrie',
        stat_active_alerts: 'Aktive Alarme',
        stat_port_scans: 'Port-Scans',
        stat_syn_floods: 'SYN-Floods',
        stat_brute_force: 'Brute-Force',
        title_recent_alerts: 'Aktuelle Sicherheitswarnungen',
        title_top_ips: 'Häufigste Angreifer-Hosts',
        card_node_count: 'Knotenanzahl nach Schwachstelle',
        tile_monitored_nodes: 'Überwacht',
        tile_critical: 'Kritisch',
        tile_high: 'Hoch',
        tile_medium: 'Mittel',
        card_vuln_count: 'Bedrohungsanzahl nach Schweregrad',
        card_risk_score: 'Kombinierte Risikobewertung',
        gauge_caption: 'Gewichteter arithmetischer Mittelwert der Host-Schwachstellenwerte.',
        title_detailed_forensics: 'Live-Bedrohungs- und Schwachstellen-Forensik',
        title_top_vulns: 'Top erkannte Schwachstellen & CVEs',
        title_dist_chart: 'Bedrohungsverteilung nach Infrastruktur-Betriebssystem',
        filter_health: 'Gesundheitsstatus',
        filter_tracked: 'Erfasst in',
        filter_os: 'Betriebssystem- / Gerätefamilie',
        title_node_inventory: 'Liste der überwachten Knoten',
        title_sig_registry: 'Katalog bekannter Netzwerksignaturen',
        title_threat_map: 'Interaktive weltweite Bedrohungskarte',
        title_wan_traffic: 'WAN-Verkehrsfehler- und Verwerfungstelemetrie',
        title_sensor_health: 'Hardware- & Sensor-Gesundheitsstatus',
        cap_badge: 'PLATTFORMFUNKTIONEN',
        cap_title: 'Tiefer Einblick in die Netzwerksicherheit',
        cap_subtitle: 'NetSentinel bietet mehrschichtige Paketinspektion und Anomalieerkennung.',
        cap_protocol_title: 'Protokollanalyse',
        cap_protocol_desc: 'Tiefgehende Inspektion von Paket-Headern und Transportschichtsitzungen.',
        cap_threat_title: 'Bedrohungserkennung',
        cap_threat_desc: 'Schnelle Korrelation von Angriffsmustern einschließlich Port-Sweeps.',
        cap_logging_title: 'Umfassende Protokollierung',
        cap_logging_desc: 'Strukturierte Persistenz in SQLite mit WAL-Modus für SIEM-Forensik.',
        cap_engine_title: 'Dual-Engine-Architektur',
        cap_engine_desc: 'Kombiniert signaturbasierte Erkennung mit statistischen ML-Anomalieschwellen.',
        cap_perf_title: 'Hohe Leistung',
        cap_perf_desc: 'Entwickelt auf Java 21 Project Loom virtuellen Threads für Skalierbarkeit.',
        cap_vis_title: 'Netzwerksichtbarkeit',
        cap_vis_desc: 'Echtzeit-SOC-Überwachung mit Pulswellenformen und Risikoskalen.'
    },
    fr: {
        nav_dashboards: 'MES TABLEAUX DE BORD',
        nav_sec_ops: 'OPÉRATIONS DE SÉCURITÉ',
        menu_live_soc: 'Rythme de Menace SOC en Direct',
        menu_vuln_risk: 'Tableau de Vulnérabilité et Risque',
        menu_nodes: 'Inventaire des Nœuds et Hôtes',
        menu_threat_map: 'Carte Mondiale des Menaces et WAN',
        menu_signatures: 'Registre des Signatures de Menaces',
        nav_knowledge: 'CONNAISSANCES ET ARCHITECTURE',
        menu_capabilities_faq: 'Capacités et Base de Connaissances',
        nav_alerts: 'ALERTES ET ACTIVITÉ',
        menu_active_stream: 'Flux d\'Alertes en Temps Réel',
        menu_attack_vectors: 'Signatures de Menaces & Vecteurs d\'Attaque',
        nav_resources: 'RESSOURCES',
        menu_faq: 'FAQ Style SolarWinds',
        menu_capabilities: 'Fonctionnalités Clés de Zeek',
        live_status: 'EN DIRECT',
        btn_clear: 'Effacer',
        btn_logout: 'Déconnexion',
        sim_bar_title: '⚡ Déclencheurs d\'Attaque Interactifs',
        sim_port_scan: 'Scan de Ports',
        sim_syn_flood: 'Inondation SYN',
        sim_brute_force: 'Force Brute (SSH)',
        sim_pcap_replay: 'Rejouer .pcap',
        title_live_rhythm: 'Moniteur de Rythme de Menace en Direct',
        title_threat_breakdown: 'Télémétrie d\'Incidents',
        stat_active_alerts: 'Alertes Actives',
        stat_port_scans: 'Scans de Port',
        stat_syn_floods: 'Inondations SYN',
        stat_brute_force: 'Force Brute',
        title_recent_alerts: 'Alertes de Sécurité Récentes',
        title_top_ips: 'Principaux Hôtes Attaquants',
        card_node_count: 'Nombre de Nœuds par Vulnérabilité',
        tile_monitored_nodes: 'Surveillés',
        tile_critical: 'Critique',
        tile_high: 'Élevé',
        tile_medium: 'Moyen',
        card_vuln_count: 'Nombre de Menaces par Gravité',
        card_risk_score: 'Score de Risque Combiné',
        gauge_caption: 'Moyenne arithmétique pondérée des scores de vulnérabilité des hôtes.',
        title_detailed_forensics: 'Télémétrie Forensique des Menaces et Vulnérabilités',
        title_top_vulns: 'Top Vulnérabilités Détectées et CVEs',
        title_dist_chart: 'Distribution des Menaces par Système d\'Exploitation',
        filter_health: 'État de Santé',
        filter_tracked: 'Suivi Dans',
        filter_os: 'Famille d\'OS / Appareil',
        title_node_inventory: 'Liste des Nœuds Surveillés',
        title_sig_registry: 'Catalogue des Signatures Réseau Connues',
        title_threat_map: 'Carte Mondiale Interactive des Menaces',
        title_wan_traffic: 'Télémétrie des Erreurs et Rejets WAN',
        title_sensor_health: 'Santé du Matériel et des Capteurs',
        cap_badge: 'FONCTIONNALITÉS DE LA PLATEFORME',
        cap_title: 'Visibilité Approfondie sur la Sécurité Réseau',
        cap_subtitle: 'NetSentinel offre une inspection multicouche des paquets et la détection d\'anomalies.',
        cap_protocol_title: 'Analyse de Protocoles',
        cap_protocol_desc: 'Inspection détaillée des en-têtes de paquets et sessions de transport TCP/UDP.',
        cap_threat_title: 'Détection des Menaces',
        cap_threat_desc: 'Corrélation rapide des schémas d\'attaque y compris les balayages de ports.',
        cap_logging_title: 'Journalisation Complète',
        cap_logging_desc: 'Persistance structurée dans SQLite en mode WAL pour l\'analyse médico-légale SIEM.',
        cap_engine_title: 'Architecture à Double Moteur',
        cap_engine_desc: 'Combine la correspondance de signatures avec les seuils statistiques d\'anomalies ML.',
        cap_perf_title: 'Haute Performance',
        cap_perf_desc: 'Conçu sur les threads virtuels Java 21 Project Loom pour une grande concurrence.',
        cap_vis_title: 'Visibilité Réseau',
        cap_vis_desc: 'Surveillance SOC en direct avec formes d\'ondes de rythme de menace.'
    }
};

let currentLang = 'en';

function initLanguage() {
    const savedLang = localStorage.getItem('nsm_lang') || 'en';
    setLanguage(savedLang);
}

function setLanguage(lang) {
    if (!i18n[lang]) lang = 'en';
    currentLang = lang;
    localStorage.setItem('nsm_lang', lang);

    const labels = {
        en: 'English',
        es: 'Español',
        de: 'Deutsch',
        fr: 'Français'
    };

    const flagSvgs = {
        en: '<svg class="lang-flag-svg" viewBox="0 0 20 14" xmlns="http://www.w3.org/2000/svg"><rect width="20" height="14" fill="#b22234"/><path d="M0 2.15h20M0 4.31h20M0 6.46h20M0 8.62h20M0 10.77h20M0 12.92h20" stroke="#fff" stroke-width="1.08"/><rect width="8" height="7.54" fill="#3c3b6e"/><circle cx="2" cy="2" r="0.6" fill="#fff"/><circle cx="4" cy="2" r="0.6" fill="#fff"/><circle cx="6" cy="2" r="0.6" fill="#fff"/><circle cx="3" cy="3.8" r="0.6" fill="#fff"/><circle cx="5" cy="3.8" r="0.6" fill="#fff"/><circle cx="2" cy="5.6" r="0.6" fill="#fff"/><circle cx="4" cy="5.6" r="0.6" fill="#fff"/><circle cx="6" cy="5.6" r="0.6" fill="#fff"/></svg>',
        es: '<svg class="lang-flag-svg" viewBox="0 0 20 14" xmlns="http://www.w3.org/2000/svg"><rect width="20" height="3.5" fill="#aa151b"/><rect y="3.5" width="20" height="7" fill="#f1bf00"/><rect y="10.5" width="20" height="3.5" fill="#aa151b"/><circle cx="5" cy="7" r="1.6" fill="#aa151b"/></svg>',
        de: '<svg class="lang-flag-svg" viewBox="0 0 20 14" xmlns="http://www.w3.org/2000/svg"><rect width="20" height="4.67" fill="#000000"/><rect y="4.67" width="20" height="4.67" fill="#dd0000"/><rect y="9.34" width="20" height="4.66" fill="#ffce00"/></svg>',
        fr: '<svg class="lang-flag-svg" viewBox="0 0 20 14" xmlns="http://www.w3.org/2000/svg"><rect width="6.67" height="14" fill="#002395"/><rect x="6.67" width="6.66" height="14" fill="#ffffff"/><rect x="13.33" width="6.67" height="14" fill="#ed2939"/></svg>'
    };

    const labelEl = document.getElementById('currentLangLabel');
    if (labelEl) labelEl.textContent = labels[lang];

    const flagEl = document.getElementById('currentLangFlag');
    if (flagEl && flagSvgs[lang]) flagEl.innerHTML = flagSvgs[lang];

    // Update active state in dropdown
    document.querySelectorAll('.lang-option').forEach(el => {
        el.classList.toggle('active', el.textContent.includes(labels[lang]));
    });

    // Translate all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key === 'live_status' && !isLive) {
            el.textContent = 'PAUSED';
            return;
        }
        if (i18n[lang] && i18n[lang][key]) {
            el.textContent = i18n[lang][key];
        }
    });
}

// ==========================================
// SPA MULTI-VIEW NAVIGATION ROUTER
// ==========================================
// SPA MULTI-VIEW NAVIGATION ROUTER & DROPDOWNS
// ==========================================
function switchView(viewId) {
    document.querySelectorAll('.view-pane').forEach(el => {
        el.classList.remove('active');
    });

    const target = document.getElementById(viewId);
    if (target) {
        target.classList.add('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // Trigger canvas resize when switching to live view
    if (viewId === 'view-live-soc' && canvas) {
        setTimeout(resizeCanvas, 50);
    }

    if (viewId === 'view-signatures') {
        syncSignaturesWithAlerts(cachedAlerts);
    }

    if (viewId === 'view-threat-map') {
        if (currentMapMode === 'globe') {
            if (!threatGlobe) {
                initGlobeMap();
            } else {
                setTimeout(() => {
                    const c = document.getElementById('globeThreatMap');
                    if (c && c.clientWidth > 0 && threatGlobe) threatGlobe.width(c.clientWidth);
                    renderThreatGlobeData();
                }, 80);
            }
        } else {
            if (!leafletThreatMap) {
                initLeafletMap();
            } else {
                setTimeout(() => {
                    try { leafletThreatMap.invalidateSize(); } catch (e) {}
                    renderThreatMap();
                }, 80);
            }
        }
        initWanCanvas();
        updateSensorHealthDonut();
    }

    // Close any open navigation dropdowns
    closeAllDropdowns();
}

function initDropdowns() {
    const dashboardsBtn = document.getElementById('navDashboardsBtn');
    const alertsBtn = document.getElementById('navAlertsBtn');
    const langBtn = document.getElementById('langSelectorBtn');

    function toggleDropdown(btn) {
        if (!btn) return;
        const parent = btn.closest('.nav-item') || btn.closest('.lang-selector');
        if (!parent) return;
        const wasOpen = parent.classList.contains('open');
        closeAllDropdowns();
        if (!wasOpen) {
            parent.classList.add('open');
        }
    }

    if (dashboardsBtn) {
        dashboardsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            toggleDropdown(dashboardsBtn);
        });
    }

    if (alertsBtn) {
        alertsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            toggleDropdown(alertsBtn);
        });
    }

    if (langBtn) {
        langBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            toggleDropdown(langBtn);
        });
    }

    // Clicking any dropdown option navigates and closes menus
    document.querySelectorAll('.dropdown-item, .lang-option').forEach(item => {
        item.addEventListener('click', () => {
            closeAllDropdowns();
        });
    });

    // Clicking anywhere outside closes all open menus
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.nav-item') && !e.target.closest('.lang-selector')) {
            closeAllDropdowns();
        }
    });
}

function closeAllDropdowns() {
    document.querySelectorAll('.nav-item.open, .lang-selector.open').forEach(el => {
        el.classList.remove('open');
    });
    document.querySelectorAll('.nav-dropdown.show, .lang-dropdown.show').forEach(el => {
        el.classList.remove('show');
    });
}

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

function playAlertAlarm(severity = 'high') {
    if (!soundEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;
        const now = ctx.currentTime;
        const sev = (severity || 'high').toLowerCase();

        if (sev === 'critical' || sev === 'high') {
            // ==========================================
            // TACTICAL SOC EMERGENCY KLAXON (2-Pulse High Alert)
            // Loud, dual-harmonic urgent warning alarm
            // ==========================================
            const masterGain = ctx.createGain();
            masterGain.gain.setValueAtTime(0.75, now);
            masterGain.connect(ctx.destination);

            // Pulse 1: 0.00s -> 0.18s
            const osc1a = ctx.createOscillator();
            const osc1b = ctx.createOscillator();
            const gain1 = ctx.createGain();

            osc1a.type = 'sawtooth';
            osc1b.type = 'square';
            osc1a.frequency.setValueAtTime(850, now);
            osc1a.frequency.exponentialRampToValueAtTime(1350, now + 0.16);
            osc1b.frequency.setValueAtTime(854, now);
            osc1b.frequency.exponentialRampToValueAtTime(1360, now + 0.16);

            gain1.gain.setValueAtTime(0.7, now);
            gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.18);

            osc1a.connect(gain1);
            osc1b.connect(gain1);
            gain1.connect(masterGain);

            osc1a.start(now);
            osc1b.start(now);
            osc1a.stop(now + 0.18);
            osc1b.stop(now + 0.18);

            // Pulse 2: 0.22s -> 0.44s (Slightly higher pitch for maximum urgency)
            const p2Start = now + 0.22;
            const osc2a = ctx.createOscillator();
            const osc2b = ctx.createOscillator();
            const gain2 = ctx.createGain();

            osc2a.type = 'sawtooth';
            osc2b.type = 'square';
            osc2a.frequency.setValueAtTime(950, p2Start);
            osc2a.frequency.exponentialRampToValueAtTime(1550, p2Start + 0.20);
            osc2b.frequency.setValueAtTime(955, p2Start);
            osc2b.frequency.exponentialRampToValueAtTime(1560, p2Start + 0.20);

            gain2.gain.setValueAtTime(0.75, p2Start);
            gain2.gain.exponentialRampToValueAtTime(0.01, p2Start + 0.22);

            osc2a.connect(gain2);
            osc2b.connect(gain2);
            gain2.connect(masterGain);

            osc2a.start(p2Start);
            osc2b.start(p2Start);
            osc2a.stop(p2Start + 0.22);
            osc2b.stop(p2Start + 0.22);

        } else if (sev === 'medium') {
            // Medium Severity: Distinct dual-tone warning chime
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(700, now);
            osc.frequency.exponentialRampToValueAtTime(1050, now + 0.26);

            gain.gain.setValueAtTime(0.55, now);
            gain.gain.exponentialRampToValueAtTime(0.01, now + 0.28);

            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.28);

        } else {
            // Low Severity: Single crisp cyber ping
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(800, now);
            osc.frequency.exponentialRampToValueAtTime(600, now + 0.15);

            gain.gain.setValueAtTime(0.4, now);
            gain.gain.exponentialRampToValueAtTime(0.01, now + 0.15);

            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now);
            osc.stop(now + 0.15);
        }
    } catch (e) {
        console.warn('Audio play error:', e);
    }
}

// ==========================================
// CANVAS & ECG THREAT RHYTHM ENGINE
// ==========================================
let canvas, ctx;
const MAX_SAMPLES = 300;
let samples = [];
let rhythmTick = 0;
let animFrameId = null;

function initEcgCanvas() {
    canvas = document.getElementById('ecgCanvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const dpr = window.devicePixelRatio || 1;
    const h = (canvas.height > 0) ? (canvas.height / dpr) : (canvas.clientHeight || 180);
    const baseline = Math.round(h * 0.5);
    samples = new Array(MAX_SAMPLES).fill(baseline);

    if (animFrameId) cancelAnimationFrame(animFrameId);
    animFrameId = requestAnimationFrame(renderEcgFrame);
}

function resizeCanvas() {
    if (!canvas || !ctx) return;
    const rect = canvas.parentElement ? canvas.parentElement.getBoundingClientRect() : null;
    const dpr = window.devicePixelRatio || 1;
    const cssWidth = (rect && rect.width > 0) ? rect.width : (canvas.clientWidth || 600);
    const cssHeight = (rect && rect.height > 0) ? rect.height : (canvas.clientHeight || 180);

    canvas.width = Math.round(cssWidth * dpr);
    canvas.height = Math.round(cssHeight * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const baseline = Math.round(cssHeight * 0.5);
    if (!samples || samples.length === 0) {
        samples = new Array(MAX_SAMPLES).fill(baseline);
    }
}

function generateWaveSample(state, tick) {
    const dpr = window.devicePixelRatio || 1;
    const h = canvas ? (canvas.height / dpr) : 180;
    const baseline = Math.round(h * 0.5); // TRUE EXACT VERTICAL CENTER

    if (state === 'normal') {
        // Steady calm single line when no active alert is present
        return baseline;
    } else if (state === 'syn_flood') {
        // Massive high-frequency packet surge, strictly balanced around baseline (no baseline jump)
        const sin1 = Math.sin(tick * 0.55) * 34;
        const sin2 = Math.cos(tick * 1.15) * 16;
        const jitter = (Math.random() - 0.5) * 12;
        return baseline + sin1 + sin2 + jitter;
    } else if (state === 'port_scan') {
        // Rapid scanning pulses with alternating balanced peaks
        const pos = tick % 14;
        let offset = 0;
        if (pos === 2) offset = -38;
        else if (pos === 3) offset = 38;
        else if (pos === 6) offset = -30;
        else if (pos === 7) offset = 30;
        else if (pos === 10) offset = -44;
        else if (pos === 11) offset = 44;
        else offset = Math.sin(tick * 0.35) * 5 + ((Math.random() - 0.5) * 4);
        return baseline + offset;
    } else if (state === 'brute_force') {
        // Heavy burst pulses with symmetrical rebound and recovery
        const pos = tick % 32;
        let offset = 0;
        if (pos === 6) offset = -48;
        else if (pos === 7) offset = 48;
        else if (pos === 14) offset = -36;
        else if (pos === 15) offset = 36;
        else offset = Math.sin(tick * 0.18) * 4 + ((Math.random() - 0.5) * 4);
        return baseline + offset;
    }
    return baseline;
}

function renderEcgFrame() {
    if (!canvas || !ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.width / dpr;
    const h = canvas.height / dpr;
    if (w <= 0 || h <= 0) {
        animFrameId = requestAnimationFrame(renderEcgFrame);
        return;
    }

    // Only advance wave generation if LIVE
    if (isLive) {
        rhythmTick++;
        const nextSample = generateWaveSample(attackState, rhythmTick);
        samples.push(nextSample);
        if (samples.length > MAX_SAMPLES) samples.shift();
    }

    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

    // High-contrast solid dark oscilloscope screen fill in both dark and light modes
    ctx.fillStyle = isDark ? '#020617' : '#070d19';
    ctx.fillRect(0, 0, w, h);

    // Subtle background grid
    ctx.strokeStyle = isDark ? 'rgba(56, 189, 248, 0.08)' : 'rgba(56, 189, 248, 0.16)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x < w; x += 30) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
    }
    for (let y = 0; y < h; y += 30) {
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
    }
    ctx.stroke();

    // Isoelectric Center Guideline (exact horizontal center line)
    ctx.strokeStyle = !isLive ? 'rgba(245, 158, 11, 0.4)' : (isDark ? 'rgba(56, 189, 248, 0.25)' : 'rgba(56, 189, 248, 0.38)');
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, Math.round(h * 0.5));
    ctx.lineTo(w, Math.round(h * 0.5));
    ctx.stroke();
    ctx.setLineDash([]);

    // Waveform line color
    const colors = {
        normal: '#10b981',
        port_scan: '#f59e0b',
        syn_flood: '#ef4444',
        brute_force: '#c084fc'
    };
    const strokeColor = !isLive ? '#f59e0b' : (colors[attackState] || '#10b981');

    ctx.beginPath();
    const dx = w / (MAX_SAMPLES - 1);
    for (let i = 0; i < samples.length; i++) {
        const x = i * dx;
        const y = Math.max(6, Math.min(h - 6, samples[i]));
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.4;
    ctx.shadowColor = strokeColor;
    ctx.shadowBlur = isDark ? 8 : 6;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Glowing scan head circle (only animated when live)
    if (isLive && samples.length > 0) {
        const headX = (samples.length - 1) * dx;
        const headY = Math.max(6, Math.min(h - 6, samples[samples.length - 1]));
        ctx.beginPath();
        ctx.arc(headX, headY, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = strokeColor;
        ctx.shadowColor = strokeColor;
        ctx.shadowBlur = isDark ? 10 : 8;
        ctx.fill();
        ctx.shadowBlur = 0;
    }

    // PAUSED OVERLAY on the oscilloscope screen
    if (!isLive) {
        ctx.fillStyle = 'rgba(2, 6, 23, 0.72)';
        ctx.fillRect(0, 0, w, h);

        ctx.fillStyle = '#fbbf24';
        ctx.font = '700 13px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('⏸️  TELEMETRY FEED PAUSED • STREAM ON HOLD', w / 2, h / 2 - 10);

        ctx.fillStyle = 'rgba(148, 163, 184, 0.9)';
        ctx.font = '500 11px Inter, sans-serif';
        ctx.fillText('Click LIVE in the top navigation to resume real-time inspection', w / 2, h / 2 + 14);
    }

    animFrameId = requestAnimationFrame(renderEcgFrame);
}

function setAttackState(state) {
    attackState = state;
    if (!isLive) return; // Preserve paused state indicator while paused
    const badge = document.getElementById('rhythmBadge');
    const text = document.getElementById('rhythmText');
    if (!badge || !text) return;

    badge.className = `rhythm-badge badge-${state.replace('_', '')}`;
    if (state === 'normal') text.textContent = 'NORMAL • SYSTEM SECURE';
    else if (state === 'port_scan') text.textContent = 'WARNING • PORT SCAN DETECTED';
    else if (state === 'syn_flood') text.textContent = 'CRITICAL • SYN FLOOD ATTACK';
    else if (state === 'brute_force') text.textContent = 'ALERT • BRUTE FORCE INTRUSION';

    if (attackStateTimeout) clearTimeout(attackStateTimeout);
    if (state !== 'normal') {
        attackStateTimeout = setTimeout(() => {
            setAttackState('normal');
        }, 7000);
    }
}

// ==========================================
// POLLING & REAL-TIME DATA DISPATCHER
// ==========================================
function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
        if (isLive) {
            fetchData();
        }
    }, 1500);
}

function toggleLiveState() {
    isLive = !isLive;
    const btn = document.getElementById('btnLiveToggle');
    const txt = document.getElementById('liveStatusText');
    const badge = document.getElementById('rhythmBadge');
    const badgeText = document.getElementById('rhythmText');

    if (isLive) {
        if (btn) btn.className = 'btn btn-live';
        if (txt) txt.textContent = (i18n[currentLang] && i18n[currentLang].live_status) ? i18n[currentLang].live_status : 'LIVE';
        if (badge && badgeText) {
            badge.className = `rhythm-badge badge-${attackState.replace('_', '')}`;
            badgeText.textContent = attackState === 'normal' ? 'NORMAL • SYSTEM SECURE' : attackState.toUpperCase();
        }
        fetchData();
    } else {
        if (btn) btn.className = 'btn btn-paused';
        if (txt) txt.textContent = 'PAUSED';
        if (badge && badgeText) {
            badge.className = 'rhythm-badge badge-paused';
            badgeText.textContent = 'PAUSED • STREAM FROZEN';
        }
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
        const res = await fetch(`${API_BASE}/api/traffic-stats`, { credentials: 'include' });
        if (!res.ok) return;
        const data = await res.json();
        if (data.packets_per_sec && data.packets_per_sec.length > 0) {
            currentPps = data.packets_per_sec[data.packets_per_sec.length - 1];
            const wanRx = document.getElementById('wanRxVal');
            const wanTx = document.getElementById('wanTxVal');
            if (wanRx) wanRx.textContent = `${(currentPps * 1.8).toFixed(1)} pkts/s`;
            if (wanTx) wanTx.textContent = `${(currentPps * 0.4).toFixed(1)} pkts/s`;
        }
        updateWanStats();
    } catch (e) {}
}

let cachedAlerts = [];
let lastAlertsFingerprint = '';
let lastTopIpsFingerprint = '';
let lastSummaryJson = '';

async function fetchAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=50`, { credentials: 'include' });
        if (!res.ok) return;
        const alerts = await res.json();
        cachedAlerts = alerts || [];
        renderAlerts(cachedAlerts);
        renderDetailedVulnTable(cachedAlerts);
        updateVulnDashboardWidgets(cachedAlerts);
        syncNodesWithAlerts(cachedAlerts);
        renderThreatMap();
        updateSensorHealthDonut();
        syncSignaturesWithAlerts(cachedAlerts);

        if (cachedAlerts && cachedAlerts.length > 0) {
            const newest = cachedAlerts[0];
            const alertTime = new Date(newest.timestamp).getTime();
            const now = Date.now();
            if (now - alertTime < 8000) {
                if (newest.attack_type === 'syn_flood') setAttackState('syn_flood');
                else if (newest.attack_type === 'port_scan') setAttackState('port_scan');
                else if (newest.attack_type === 'brute_force') setAttackState('brute_force');
            } else {
                setAttackState('normal');
            }
        } else {
            setAttackState('normal');
        }
    } catch (e) {}
}

async function fetchSummary() {
    try {
        const res = await fetch(`${API_BASE}/api/summary`, { credentials: 'include' });
        if (!res.ok) return;
        const sum = await res.json();
        const json = JSON.stringify(sum);
        if (json === lastSummaryJson) return;
        lastSummaryJson = json;

        const elPort = document.getElementById('sumPortScan');
        const elBrute = document.getElementById('sumBruteForce');
        const elSyn = document.getElementById('sumSynFlood');
        const elActive = document.getElementById('activeAlertsCount');

        const pScan = sum.port_scan || 0;
        const bForce = sum.brute_force || 0;
        const sFlood = sum.syn_flood || 0;
        const total = pScan + bForce + sFlood;

        if (elPort) elPort.textContent = pScan;
        if (elBrute) elBrute.textContent = bForce;
        if (elSyn) elSyn.textContent = sFlood;
        if (elActive) elActive.textContent = total;
    } catch (e) {}
}

async function fetchTopIps() {
    try {
        const res = await fetch(`${API_BASE}/api/top-ips?limit=5`, { credentials: 'include' });
        if (!res.ok) return;
        const topIps = await res.json();
        renderTopIps(topIps);
    } catch (e) {}
}

// ==========================================
// RENDER ALERTS FEED & TOP IPS
// ==========================================
function renderAlerts(alerts) {
    if (!alerts || alerts.length === 0) {
        const container = document.getElementById('alertsContainer');
        if (lastAlertsFingerprint !== 'EMPTY' || (container && !container.innerHTML.includes('No security alerts detected'))) {
            lastAlertsFingerprint = 'EMPTY';
            if (container) {
                container.innerHTML = `
                    <div style="text-align: center; color: var(--text-muted); padding: 3rem 0; font-size: 0.85rem;">
                        🛡️ No security alerts detected yet. Listening for traffic...
                    </div>`;
            }
        }
        return;
    }

    const currentFingerprint = alerts.map(a => a.alert_id).join(',');
    if (currentFingerprint === lastAlertsFingerprint) return;

    if (lastAlertsFingerprint !== '' && lastAlertsFingerprint !== 'EMPTY') {
        const prevList = lastAlertsFingerprint.split(',');
        const hasBrandNew = alerts.some(a => !prevList.includes(a.alert_id));
        if (hasBrandNew && alerts.length > 0) {
            playAlertAlarm(alerts[0].severity);
        }
    }

    lastAlertsFingerprint = currentFingerprint;
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    container.innerHTML = alerts.map(a => {
        const timeFormatted = escapeHtml(new Date(a.timestamp).toLocaleTimeString());
        const safeAttackType = escapeHtml(a.attack_type ? a.attack_type.replace('_', ' ').toUpperCase() : 'UNKNOWN');
        const safeSeverity = escapeHtml(a.severity || 'low');
        const safeDetails = escapeHtml(a.details || 'Suspicious network behavior identified.');
        const safeSrcIp = escapeHtml(a.src_ip || '0.0.0.0');
        const safeDstIp = escapeHtml(a.dst_ip || '0.0.0.0');
        const methodTag = a.detection_method === 'ml'
            ? `<span class="badge badge-method-ml">🧠 ML MODEL</span>`
            : `<span class="badge badge-method-rule">⚙️ RULE</span>`;

        return `
            <div class="alert-card severity-${safeSeverity}">
                <div class="alert-card-header">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span class="badge badge-${safeSeverity}">[${safeSeverity.toUpperCase()}]</span>
                        <strong style="color: var(--text-primary); font-size: 0.82rem;">${safeAttackType}</strong>
                        ${methodTag}
                    </div>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${timeFormatted}</span>
                </div>
                <div class="alert-desc">${safeDetails}</div>
                <div class="alert-meta">
                    <span>Source: <strong style="color: var(--text-primary);">${safeSrcIp}</strong></span>
                    <span>Target: <strong style="color: var(--text-primary);">${safeDstIp}</strong></span>
                    <span>Confidence: <strong style="color: var(--accent-blue);">${Math.round(a.confidence * 100)}%</strong></span>
                </div>
            </div>`;
    }).join('');
}

function renderTopIps(topIps) {
    const fingerprint = JSON.stringify(topIps || []);
    if (fingerprint === lastTopIpsFingerprint) return;
    lastTopIpsFingerprint = fingerprint;

    const tbody = document.getElementById('topIpsTableBody');
    if (!tbody) return;

    if (!topIps || topIps.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">No attacking hosts detected yet</td></tr>`;
        return;
    }

    tbody.innerHTML = topIps.map(ip => `
        <tr>
            <td style="color: #f87171; font-weight: 600;">${escapeHtml(ip.src_ip)}</td>
            <td><strong style="color: var(--text-primary);">${parseInt(ip.alert_count, 10) || 0}</strong></td>
            <td style="color: var(--text-muted);">${escapeHtml(new Date(ip.last_seen).toLocaleTimeString())}</td>
        </tr>
    `).join('');
}

// ==========================================
// VIEW 2: DYNAMIC RISK, DONUT & DETAILED FORENSICS LOGIC
// ==========================================
function updateVulnDashboardWidgets(alerts) {
    const list = alerts || [];
    const total = list.length;

    // Severity breakdown from real detected alerts
    const critCount = list.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
    const highCount = list.filter(a => (a.severity || '').toLowerCase() === 'high').length;
    const medCount = list.filter(a => (a.severity || '').toLowerCase() === 'medium').length;
    const lowCount = list.filter(a => (a.severity || '').toLowerCase() === 'low').length;

    // Distinct monitored nodes involved
    const hostSet = new Set();
    list.forEach(a => {
        if (a.src_ip) hostSet.add(a.src_ip);
        if (a.dst_ip) hostSet.add(a.dst_ip);
    });
    const monitoredCount = total > 0 ? Math.max(hostSet.size, 1) : 0;

    // 1. Metric Tiles (strictly bounded inside card)
    const elMon = document.getElementById('tileTotalNodes');
    const elCrit = document.getElementById('tileCriticalNodes');
    const elHigh = document.getElementById('tileHighNodes');
    const elMed = document.getElementById('tileMediumNodes');
    if (elMon) elMon.textContent = monitoredCount.toLocaleString();
    if (elCrit) elCrit.textContent = critCount.toLocaleString();
    if (elHigh) elHigh.textContent = highCount.toLocaleString();
    if (elMed) elMed.textContent = medCount.toLocaleString();

    // 2. Donut Chart numbers & legend
    const totalEl = document.getElementById('donutTotalCount');
    if (totalEl) totalEl.textContent = total.toLocaleString();

    const legCrit = document.getElementById('legendCritCount');
    const legHigh = document.getElementById('legendHighCount');
    const legMed = document.getElementById('legendMedCount');
    const legLow = document.getElementById('legendLowCount');
    if (legCrit) legCrit.textContent = critCount.toLocaleString();
    if (legHigh) legHigh.textContent = highCount.toLocaleString();
    if (legMed) legMed.textContent = medCount.toLocaleString();
    if (legLow) legLow.textContent = lowCount.toLocaleString();

    // SVG Donut slices (Circumference ~ 339.29 for r=54)
    const C = 339.29;
    const segCrit = document.getElementById('donutSegCrit');
    const segHigh = document.getElementById('donutSegHigh');
    const segMed = document.getElementById('donutSegMed');
    const segLow = document.getElementById('donutSegLow');

    if (total === 0) {
        if (segCrit) segCrit.setAttribute('stroke-dasharray', `0 ${C}`);
        if (segHigh) segHigh.setAttribute('stroke-dasharray', `0 ${C}`);
        if (segMed) segMed.setAttribute('stroke-dasharray', `0 ${C}`);
        if (segLow) segLow.setAttribute('stroke-dasharray', `0 ${C}`);
    } else {
        const critLen = (critCount / total) * C;
        const highLen = (highCount / total) * C;
        const medLen = (medCount / total) * C;
        const lowLen = (lowCount / total) * C;

        let offset = 0;
        if (segCrit) {
            segCrit.setAttribute('stroke-dasharray', `${critLen.toFixed(1)} ${(C - critLen).toFixed(1)}`);
            segCrit.setAttribute('stroke-dashoffset', `${offset.toFixed(1)}`);
        }
        offset -= critLen;
        if (segHigh) {
            segHigh.setAttribute('stroke-dasharray', `${highLen.toFixed(1)} ${(C - highLen).toFixed(1)}`);
            segHigh.setAttribute('stroke-dashoffset', `${offset.toFixed(1)}`);
        }
        offset -= highLen;
        if (segMed) {
            segMed.setAttribute('stroke-dasharray', `${medLen.toFixed(1)} ${(C - medLen).toFixed(1)}`);
            segMed.setAttribute('stroke-dashoffset', `${offset.toFixed(1)}`);
        }
        offset -= medLen;
        if (segLow) {
            segLow.setAttribute('stroke-dasharray', `${lowLen.toFixed(1)} ${(C - lowLen).toFixed(1)}`);
            segLow.setAttribute('stroke-dashoffset', `${offset.toFixed(1)}`);
        }
    }

    // 3. Continuous Risk Score Gauge
    const pointer = document.getElementById('riskGaugePointer');
    if (pointer) {
        if (total === 0) {
            pointer.style.left = '4%';
        } else {
            const weightedScore = (critCount * 5.0 + highCount * 3.0 + medCount * 1.0 + lowCount * 0.5) / total;
            const scorePct = Math.min(95, Math.max(8, Math.round((weightedScore / 5.0) * 100)));
            pointer.style.left = `${scorePct}%`;
        }
    }
}

function renderDetailedVulnTable(alerts = cachedAlerts) {
    const tbody = document.getElementById('detailedVulnTableBody');
    const badge = document.getElementById('detailedVulnCountBadge');
    if (!tbody) return;

    const searchInput = document.getElementById('detailedVulnSearch');
    const sevSelect = document.getElementById('detailedVulnSevFilter');
    const searchTerm = (searchInput?.value || '').trim().toLowerCase();
    const sevFilter = (sevSelect?.value || 'ALL').toUpperCase();

    let filtered = alerts || [];
    if (sevFilter !== 'ALL') {
        filtered = filtered.filter(a => (a.severity || '').toUpperCase() === sevFilter);
    }
    if (searchTerm) {
        filtered = filtered.filter(a => {
            const id = (a.alert_id || '').toLowerCase();
            const type = (a.attack_type || '').toLowerCase();
            const src = (a.src_ip || '').toLowerCase();
            const dst = (a.dst_ip || '').toLowerCase();
            const details = (a.details || '').toLowerCase();
            const method = (a.detection_method || '').toLowerCase();
            return id.includes(searchTerm) || type.includes(searchTerm) ||
                   src.includes(searchTerm) || dst.includes(searchTerm) ||
                   details.includes(searchTerm) || method.includes(searchTerm);
        });
    }

    if (badge) {
        badge.textContent = `${filtered.length} Live Detection${filtered.length === 1 ? '' : 's'}`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 3rem 0; font-size: 0.85rem;">
                    🛡️ No security incidents or vulnerabilities detected matching the criteria. Listening for live traffic...
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => {
        const safeSev = escapeHtml((a.severity || 'low').toLowerCase());
        const safeId = escapeHtml(a.alert_id || 'ALT-000');
        const dateObj = new Date(a.timestamp);
        const timeFormatted = escapeHtml(dateObj.toLocaleTimeString());
        
        let typeLabel = 'Unknown Threat';
        let typeCategory = 'Network Telemetry';
        const at = (a.attack_type || '').toLowerCase();
        if (at === 'syn_flood') {
            typeLabel = '⚡ SYN Flood Surge';
            typeCategory = 'Denial of Service (DoS)';
        } else if (at === 'port_scan') {
            typeLabel = '🔍 TCP Port Scan';
            typeCategory = 'Reconnaissance Sweep';
        } else if (at === 'brute_force') {
            typeLabel = '🔑 SSH Brute Force';
            typeCategory = 'Credential Infiltration';
        } else {
            typeLabel = escapeHtml(a.attack_type ? a.attack_type.toUpperCase() : 'ANOMALY');
        }

        const safeSrc = escapeHtml(a.src_ip || '0.0.0.0');
        const safeDst = escapeHtml(a.dst_ip || '0.0.0.0');
        const safeDetails = escapeHtml(a.details || 'Suspicious network behavior identified.');
        const confPct = Math.round((a.confidence || 0.95) * 100);
        const fullThreatTitle = `${typeLabel} — ${typeCategory}`;

        const methodBadge = (a.detection_method || '').toLowerCase() === 'ml'
            ? `<span class="badge badge-method-ml" title="Unsupervised Isolation Forest Engine">🧠 ML</span>`
            : `<span class="badge badge-method-rule" title="Deterministic Stateful Rule Engine">⚙️ RULE</span>`;

        return `
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.4rem;">
                        <span class="status-dot status-dot-${safeSev}"></span>
                        <span class="badge badge-${safeSev}" style="font-size: 0.68rem; font-weight: 700; padding: 0.15rem 0.45rem;">${safeSev.toUpperCase()}</span>
                    </div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); font-size: 0.76rem;">#${safeId}</div>
                    <div style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">${timeFormatted}</div>
                </td>
                <td>
                    <div class="threat-classification-title" title="${escapeHtml(fullThreatTitle)}" style="font-weight: 700; color: var(--text-primary); font-size: 0.8rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px; cursor: help;">${typeLabel}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted); text-transform: uppercase; font-family: var(--font-mono); margin-top: 2px;">${typeCategory}</div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 600; color: #f87171; font-size: 0.78rem;">${safeSrc}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted);">Attacker</div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-blue); font-size: 0.78rem;">${safeDst}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted);">Target</div>
                </td>
                <td style="text-align: center;">${methodBadge}</td>
                <td style="text-align: center;">
                    <div style="display: inline-flex; align-items: center; gap: 0.35rem; justify-content: center;">
                        <span style="font-family: var(--font-mono); font-weight: 700; font-size: 0.76rem; color: var(--accent-blue);">${confPct}%</span>
                        <div style="width: 22px; height: 4px; background: rgba(148, 163, 184, 0.2); border-radius: 2px; overflow: hidden;">
                            <div style="width: ${confPct}%; height: 100%; background: var(--accent-blue);"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <div style="font-size: 0.74rem; color: var(--text-secondary); line-height: 1.4; word-break: break-word;">
                        ${safeDetails}
                    </div>
                </td>
                <td style="text-align: center;">
                    <span class="badge" style="background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.55rem; border-radius: 6px; display: inline-flex; align-items: center; gap: 0.3rem;" title="Threat quarantined and mitigated by NetSentinel IDS engine">
                        <span style="font-size: 0.72rem;">🛡️</span> Mitigated
                    </span>
                </td>
            </tr>`;
    }).join('');
}

function initDetailedVulnFilters() {
    const searchInput = document.getElementById('detailedVulnSearch');
    const sevSelect = document.getElementById('detailedVulnSevFilter');
    if (searchInput) {
        searchInput.addEventListener('input', () => renderDetailedVulnTable(cachedAlerts));
    }
    if (sevSelect) {
        sevSelect.addEventListener('change', () => renderDetailedVulnTable(cachedAlerts));
    }
}

// ==========================================
// VIEW 3: NODE INVENTORY & HOVER POPOVER
// ==========================================
const KNOWN_HOST_METADATA = {
    '192.168.1.1': { name: 'GATEWAY-CORE-01', os: 'Cisco IOS-XE / 802.11ax', role: 'Perimeter Gateway Router' },
    '192.168.1.100': { name: 'SRV-WEB-PROD-01', os: 'Ubuntu Linux 22.04 LTS', role: 'Primary Web & API Application Server' },
    '192.168.1.90': { name: 'HONEYPOT-DECOY-01', os: 'NetSentinel Trap Engine', role: 'Java 21 Project Loom Decoy' },
    '192.168.1.150': { name: 'SRV-DB-SQLITE-01', os: 'Debian 12 Bookworm', role: 'SQLite WAL Cluster / Audit Storage' },
    '192.168.1.10': { name: 'DC-DNS-AUTH-01', os: 'Windows Server 2022', role: 'Active Directory / DNS Authority' },
    '192.168.1.25': { name: 'SEC-MAIL-PROXY-01', os: 'Fortinet FortiOS 7.4', role: 'Mail Security Gateway & Reverse Proxy' },
    '192.168.1.45': { name: 'SW-DIST-FLOOR-1', os: 'Aruba 3810M SwitchOS', role: 'VLAN Access Layer Distribution' },
    '192.168.1.8': { name: 'SOC-ADMIN-TERM-01', os: 'macOS Sonoma (Darwin)', role: 'Administrative SOC Workstation' }
};

let currentNodesList = [];
let lastFilteredNodes = [];
let nodeCurrentPage = 1;
const nodePageSize = 6;

function syncNodesWithAlerts(alerts = cachedAlerts) {
    const nodeMap = new Map();

    // Derive inventory EXCLUSIVELY from active alerts (no static/secured placeholder nodes)

    // 2. Aggregate real live alerts to affected hosts
    (alerts || []).forEach(alert => {
        const dstIp = alert.dst_ip || alert.destIp;
        const srcIp = alert.src_ip || alert.sourceIp;
        const sev = (alert.severity || 'low').toLowerCase();

        // Register destination / target host
        if (dstIp) {
            if (!nodeMap.has(dstIp)) {
                const meta = KNOWN_HOST_METADATA[dstIp] || {
                    name: `HOST-${dstIp}`,
                    os: dstIp.startsWith('192.168.') ? 'Internal Monitored Node' : 'External Target Host',
                    role: 'Target Node / Destination'
                };
                nodeMap.set(dstIp, {
                    id: `node-${dstIp.replace(/[^a-zA-Z0-9]/g, '-')}`,
                    name: meta.name,
                    ip: dstIp,
                    os: meta.os,
                    role: meta.role,
                    crit: 0, high: 0, med: 0, low: 0, total: 0, alerts: [], lastSeen: null
                });
            }
            const node = nodeMap.get(dstIp);
            node.total++;
            if (sev === 'critical') node.crit++;
            else if (sev === 'high') node.high++;
            else if (sev === 'medium') node.med++;
            else node.low++;
            node.alerts.push(alert);
            if (!node.lastSeen || new Date(alert.timestamp) > new Date(node.lastSeen)) {
                node.lastSeen = alert.timestamp;
            }
        }

        // Register source / attacker host
        if (srcIp && srcIp !== '0.0.0.0') {
            if (!nodeMap.has(srcIp)) {
                const isLocal = srcIp.startsWith('192.168.') || srcIp.startsWith('10.');
                const meta = KNOWN_HOST_METADATA[srcIp] || {
                    name: isLocal ? `INTRUDER-${srcIp}` : `EXT-ATTACKER-${srcIp}`,
                    os: isLocal ? 'Compromised LAN Endpoint' : 'External WAN Ingress',
                    role: isLocal ? 'Internal Threat Vector' : 'External Adversary IP'
                };
                nodeMap.set(srcIp, {
                    id: `node-${srcIp.replace(/[^a-zA-Z0-9]/g, '-')}`,
                    name: meta.name,
                    ip: srcIp,
                    os: meta.os,
                    role: meta.role,
                    crit: 0, high: 0, med: 0, low: 0, total: 0, alerts: [], lastSeen: null
                });
            }
            const srcNode = nodeMap.get(srcIp);
            srcNode.total++;
            if (sev === 'critical') srcNode.crit++;
            else if (sev === 'high') srcNode.high++;
            else if (sev === 'medium') srcNode.med++;
            else srcNode.low++;
            srcNode.alerts.push(alert);
            if (!srcNode.lastSeen || new Date(alert.timestamp) > new Date(srcNode.lastSeen)) {
                srcNode.lastSeen = alert.timestamp;
            }
        }
    });

    // 3. Compute health, risk score, and tracking category
    const now = Date.now();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    nodeMap.forEach(n => {
        // Health state: dynamically determined by real alert severity
        if (n.crit > 0) {
            n.health = 'critical';
            n.statusDot = 'critical';
        } else if (n.high > 0) {
            n.health = 'high';
            n.statusDot = 'high';
        } else {
            n.health = 'medium';
            n.statusDot = 'medium';
        }

        // Risk score (0 - 100)
        const calculated = Math.round(n.crit * 28 + n.high * 16 + n.med * 9 + n.low * 3);
        n.risk = Math.min(100, Math.max(12, calculated));

        // Tracking category (Last 7 days vs Older)
        if (n.lastSeen) {
            const diff = now - new Date(n.lastSeen).getTime();
            if (diff <= sevenDaysMs) {
                n.tracked = 'Last 7 days';
                n.trackingCategory = 'last_7_days';
            } else {
                n.tracked = 'Older than 7 days';
                n.trackingCategory = 'older';
            }
        } else {
            n.tracked = 'Last 7 days';
            n.trackingCategory = 'last_7_days';
        }
    });

    currentNodesList = Array.from(nodeMap.values());

    // 4. Update sidebar filter count badges
    updateNodeFilterBadges();

    // 5. Apply filters, sorting, and pagination
    filterNodes();
}

function updateNodeFilterBadges() {
    let critCount = 0, highCount = 0, medCount = 0;
    let last7Count = 0, olderCount = 0;

    currentNodesList.forEach(n => {
        if (n.health === 'critical') critCount++;
        else if (n.health === 'high') highCount++;
        else if (n.health === 'medium') medCount++;

        if (n.trackingCategory === 'last_7_days') last7Count++;
        else olderCount++;
    });

    const bCrit = document.getElementById('badgeHealthCritical');
    const bHigh = document.getElementById('badgeHealthHigh');
    const bMed = document.getElementById('badgeHealthMedium');
    const b7 = document.getElementById('badgeTracked7Days');
    const bOld = document.getElementById('badgeTrackedOlder');

    if (bCrit) bCrit.textContent = critCount;
    if (bHigh) bHigh.textContent = highCount;
    if (bMed) bMed.textContent = medCount;
    if (b7) b7.textContent = last7Count;
    if (bOld) bOld.textContent = olderCount;
}

function filterNodes() {
    const query = (document.getElementById('nodeSearchInput')?.value || '').toLowerCase().trim();

    // Read Health filters
    const chkCrit = document.getElementById('filterHealthCritical')?.checked || false;
    const chkHigh = document.getElementById('filterHealthHigh')?.checked || false;
    const chkMed = document.getElementById('filterHealthMedium')?.checked || false;
    const anyHealthFiltered = chkCrit || chkHigh || chkMed;

    // Read Tracking filters
    const chk7 = document.getElementById('filterTracked7Days')?.checked || false;
    const chkOld = document.getElementById('filterTrackedOlder')?.checked || false;
    const anyTrackFiltered = chk7 || chkOld;

    // Filter array
    let filtered = currentNodesList.filter(n => {
        // Health matching
        if (anyHealthFiltered) {
            const matchesHealth = (chkCrit && n.health === 'critical') ||
                                  (chkHigh && n.health === 'high') ||
                                  (chkMed && n.health === 'medium');
            if (!matchesHealth) return false;
        }

        // Tracking matching
        if (anyTrackFiltered) {
            const matchesTracking = (chk7 && n.trackingCategory === 'last_7_days') ||
                                    (chkOld && n.trackingCategory === 'older');
            if (!matchesTracking) return false;
        }

        // Search query matching
        if (query) {
            const matchesQuery = n.name.toLowerCase().includes(query) ||
                                 n.ip.toLowerCase().includes(query) ||
                                 n.os.toLowerCase().includes(query) ||
                                 n.role.toLowerCase().includes(query);
            if (!matchesQuery) return false;
        }

        return true;
    });

    // Sorting:
    // Health sorting order: Critical (1) > High (2) > Medium (3)
    const healthRank = { 'critical': 1, 'high': 2, 'medium': 3, 'low': 4 };
    const trackRank = { 'last_7_days': 1, 'older': 2 };

    filtered.sort((a, b) => {
        if (anyHealthFiltered) {
            const diffH = (healthRank[a.health] || 99) - (healthRank[b.health] || 99);
            if (diffH !== 0) return diffH;
        }
        if (anyTrackFiltered) {
            const diffT = (trackRank[a.trackingCategory] || 99) - (trackRank[b.trackingCategory] || 99);
            if (diffT !== 0) return diffT;
        }
        // Secondary sort: highest risk score first, then highest total alerts
        if (b.risk !== a.risk) return b.risk - a.risk;
        return b.total - a.total;
    });

    renderNodesTable(filtered);
}

function renderNodesTable(nodes = currentNodesList) {
    lastFilteredNodes = nodes;
    const totalNodes = nodes.length;
    const totalPages = Math.max(1, Math.ceil(totalNodes / nodePageSize));

    // Clamp current page
    if (nodeCurrentPage > totalPages) nodeCurrentPage = totalPages;
    if (nodeCurrentPage < 1) nodeCurrentPage = 1;

    const startIdx = totalNodes === 0 ? 0 : (nodeCurrentPage - 1) * nodePageSize;
    const endIdx = Math.min(startIdx + nodePageSize, totalNodes);
    const pageSlice = nodes.slice(startIdx, endIdx);

    const tbody = document.getElementById('nodesTableBody');
    if (!tbody) return;

    if (pageSlice.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: 3rem; color: var(--text-muted); font-size: 0.85rem;">
                    🛡️ No monitored threat nodes detected. Inventory populates dynamically as network alerts occur.
                </td>
            </tr>`;
    } else {
        tbody.innerHTML = pageSlice.map(n => {
            const safeName = escapeHtml(n.name);
            const safeIp = escapeHtml(n.ip);
            const safeOs = escapeHtml(n.os);
            const safeRole = escapeHtml(n.role);
            const safeTracked = escapeHtml(n.tracked);
            const healthUpper = escapeHtml(n.health.toUpperCase());

            return `
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.4rem;">
                        <span class="status-dot status-dot-${n.statusDot}"></span>
                        <span class="badge badge-${n.health}" style="font-size: 0.68rem; font-weight: 700;">${healthUpper}</span>
                    </div>
                </td>
                <td>
                    <span class="node-interactive-link" onmouseenter="showNodePopover(event, '${safeName}')" onmouseleave="hideNodePopover()">
                        ${safeName}
                    </span>
                    <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">${safeIp}</div>
                </td>
                <td style="color: var(--text-secondary); font-size: 0.76rem;">
                    <div style="font-weight: 600; color: var(--text-primary);">${safeOs}</div>
                    <div style="font-size: 0.7rem; color: var(--text-muted);">${safeRole}</div>
                </td>
                <td style="color: var(--text-muted); font-size: 0.74rem; font-family: var(--font-mono); white-space: nowrap;">
                    📅 ${safeTracked}
                </td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.45rem;">
                        <div class="mini-risk-bar" title="Calculated Risk: ${n.risk}%">
                            <div class="mini-risk-indicator" style="left: ${n.risk}%;"></div>
                        </div>
                        <span style="font-size: 0.74rem; font-weight: 800; font-family: var(--font-mono); color: ${n.risk >= 70 ? '#ef4444' : (n.risk >= 40 ? '#f59e0b' : '#10b981')};">${n.risk}%</span>
                    </div>
                </td>
                <td>
                    <span class="badge" style="font-family: var(--font-mono); font-weight: 800; font-size: 0.76rem; background: var(--bg-surface-elevated); border: 1px solid var(--card-border); color: var(--text-primary); padding: 0.15rem 0.5rem;">${n.total}</span>
                </td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.74rem; font-family: var(--font-mono);">
                        <span style="color: #ef4444; font-weight: 700;" title="Critical Incidents">● ${n.crit}</span>
                        <span style="color: #ea580c; font-weight: 700;" title="High Severity">● ${n.high}</span>
                        <span style="color: #eab308; font-weight: 700;" title="Medium Severity">● ${n.med}</span>
                        <span style="color: #0284c7; font-weight: 700;" title="Low / Informational">● ${n.low}</span>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    // Update Pagination Controls
    const infoEl = document.getElementById('nodesPaginationInfo');
    if (infoEl) {
        infoEl.textContent = totalNodes === 0
            ? 'Showing 0–0 of 0 Monitored Nodes'
            : `Showing ${startIdx + 1}–${endIdx} of ${totalNodes} Monitored Nodes`;
    }

    const btnsContainer = document.getElementById('nodesPaginationBtns');
    if (btnsContainer) {
        if (totalNodes === 0) {
            btnsContainer.innerHTML = '';
        } else {
            let buttonsHtml = '';

            // Prev Button
            buttonsHtml += `<button class="btn" style="padding: 0.2rem 0.6rem; ${nodeCurrentPage <= 1 ? 'opacity: 0.4; cursor: not-allowed;' : ''}" ${nodeCurrentPage <= 1 ? 'disabled' : ''} onclick="changeNodePage(${nodeCurrentPage - 1})">&lt;</button>`;

            // Numbered page buttons
            for (let p = 1; p <= totalPages; p++) {
                const isActive = p === nodeCurrentPage;
                buttonsHtml += `<button class="btn ${isActive ? 'btn-live' : ''}" style="padding: 0.2rem 0.6rem; min-width: 28px;" onclick="changeNodePage(${p})">${p}</button>`;
            }

            // Next Button
            buttonsHtml += `<button class="btn" style="padding: 0.2rem 0.6rem; ${nodeCurrentPage >= totalPages ? 'opacity: 0.4; cursor: not-allowed;' : ''}" ${nodeCurrentPage >= totalPages ? 'disabled' : ''} onclick="changeNodePage(${nodeCurrentPage + 1})">&gt;</button>`;

            btnsContainer.innerHTML = buttonsHtml;
        }
    }
}

function changeNodePage(page) {
    nodeCurrentPage = page;
    renderNodesTable(lastFilteredNodes);
}

function showNodePopover(event, nodeName) {
    const pop = document.getElementById('nodeHoverPopover');
    if (!pop) return;

    const node = currentNodesList.find(n => n.name === nodeName || n.ip === nodeName);
    if (!node) return;

    const elName = document.getElementById('popoverNodeName');
    const elIp = document.getElementById('popoverIp');
    const elType = document.getElementById('popoverType');
    const elPing = document.getElementById('popoverPing');
    const elCpu = document.getElementById('popoverCpu');
    const elRam = document.getElementById('popoverRam');
    const elFlow = document.getElementById('popoverFlow');

    if (elName) elName.textContent = node.name;
    if (elIp) elIp.textContent = node.ip;
    if (elType) elType.textContent = `${node.os} — ${node.role}`;
    if (elPing) elPing.textContent = `${Math.max(1, Math.round(node.risk / 12))} ms`;
    if (elCpu) elCpu.textContent = `${Math.min(99, Math.max(4, Math.round(node.risk * 0.95)))} %`;
    if (elRam) elRam.textContent = `${Math.min(95, Math.max(18, Math.round(node.risk * 0.8 + 20)))} %`;
    if (elFlow) elFlow.textContent = node.total > 0 ? `${node.total} real-time security alerts` : 'Healthy baseline telemetry';

    pop.style.left = `${event.clientX + 16}px`;
    pop.style.top = `${event.clientY - 30}px`;
    pop.classList.add('visible');
}

function hideNodePopover() {
    const pop = document.getElementById('nodeHoverPopover');
    if (pop) pop.classList.remove('visible');
}

// ==========================================
// VIEW 4: THREAT SIGNATURE REGISTRY & MODAL
// ==========================================
const THREAT_SIGNATURES_REGISTRY = [
    {
        id: 'SIG-1001',
        cve: 'CVE-2023-48795',
        mitre: 'T1110.001',
        name: 'SSH Automated Brute Force Intrusion',
        desc: 'Rapid sequence of authentication attempts against SSH daemon (Port 22) exceeding threshold, indicating automated credential dictionary brute-forcing.',
        proto: 'TCP/22',
        engine: 'Module 2 (Heuristic Rule Engine)',
        score: 8.8,
        sev: 'critical',
        status: 'Active (Armored)',
        ruleLogic: 'alert tcp any any -> $HOME_NET 22 (msg:"NETSENTINEL SSH Brute Force Detected"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 10, seconds 30; classtype:attempted-admin; sid:1001; rev:2;)',
        nodes: '192.168.1.77 (Attacker IP) ➔ 10.0.0.1:22 (SSH Gateway Node)',
        simType: 'brute-force',
        advisory: 'https://nvd.nist.gov/vuln/detail/CVE-2023-48795'
    },
    {
        id: 'SIG-1002',
        cve: 'CWE-400',
        mitre: 'T1498.001',
        name: 'TCP SYN Flood Volumetric Denial-of-Service',
        desc: 'High-frequency burst of half-open TCP SYN frames targeting HTTP/HTTPS ports without completing the 3-way handshake, exhausting connection state tables.',
        proto: 'TCP/80,443',
        engine: 'Module 2 (Heuristic Rule Engine)',
        score: 9.3,
        sev: 'critical',
        status: 'Active (Armored)',
        ruleLogic: 'alert tcp any any -> $HOME_NET [80,443] (msg:"NETSENTINEL Volumetric SYN Flood Surge"; flags:S,12; threshold:type threshold, track by_dst, count 50, seconds 2; classtype:denial-of-service; sid:1002; rev:1;)',
        nodes: '192.168.1.99 (Attacker IP) ➔ 10.0.0.1:80 (Web Cluster Ingress)',
        simType: 'syn-flood',
        advisory: 'https://cwe.mitre.org/data/definitions/400.html'
    },
    {
        id: 'SIG-1003',
        cve: 'CWE-200',
        mitre: 'T1046',
        name: 'TCP Multi-Port Reconnaissance Sweep',
        desc: 'Sequential connection probing across 15+ destination ports within a 5-second interval, indicative of active Nmap reconnaissance scanning.',
        proto: 'TCP/Multi',
        engine: 'Module 2 (Heuristic Rule Engine)',
        score: 7.5,
        sev: 'high',
        status: 'Active (Armored)',
        ruleLogic: 'alert tcp any any -> $HOME_NET any (msg:"NETSENTINEL Horizontal Port Scan Sweep"; flow:to_server; detection_filter:track by_src, count 15, seconds 5; classtype:network-scan; sid:1003; rev:3;)',
        nodes: '192.168.1.50 (Attacker IP) ➔ 10.0.0.1:20-45 (Monitored Subnet)',
        simType: 'port-scan',
        advisory: 'https://attack.mitre.org/techniques/T1046/'
    },
    {
        id: 'SIG-1004',
        cve: 'LOOM-DECOY-01',
        mitre: 'T1046',
        name: 'Java 21 Loom Decoy Honeypot Trap',
        desc: 'Direct connection probe on lightweight unadvertised zero-interaction decoy honeypot ports (2222, 8088, 8888, 9090) powered by virtual threads.',
        proto: 'TCP/2222,8088,8888,9090',
        engine: 'Module 2 & Project Loom Honeypot',
        score: 9.0,
        sev: 'critical',
        status: 'Active (Armored)',
        ruleLogic: 'alert tcp any any -> $HOME_NET [2222,8088,8888,9090] (msg:"NETSENTINEL Virtual Decoy Honeypot Trap Triggered"; flow:to_server; classtype:unauthorized-access-attempt; sid:1004; rev:1;)',
        nodes: '0.0.0.0:2222, 0.0.0.0:8088, 0.0.0.0:8888, 0.0.0.0:9090 (Virtual Decoys)',
        simType: null,
        advisory: 'https://attack.mitre.org/techniques/T1046/'
    },
    {
        id: 'SIG-1005',
        cve: 'ML-ISOFOREST-01',
        mitre: 'T1071',
        name: 'Isolation Forest Flow Entropy & Volumetric Anomaly',
        desc: 'Statistical packet size variance and flow volume deviation detected by unsupervised Isolation Forest ML model, identifying zero-day anomalous traffic.',
        proto: 'IP/Flow',
        engine: 'Module 3 (Isolation Forest ML Engine)',
        score: 7.8,
        sev: 'medium',
        status: 'Active (Armored)',
        ruleLogic: 'anomaly_model: IsolationForest(contamination=0.01, n_estimators=100); features: [packet_rate, byte_rate, syn_ratio, entropy_deviation]; score_threshold: -0.15; sid:1005;',
        nodes: 'All Ingress/Egress Flows (Statistical Feature Baseline)',
        simType: null,
        advisory: 'https://attack.mitre.org/techniques/T1071/'
    }
];

function mapAlertToMitre(alert) {
    if (!alert) return null;
    const type = (alert.attack_type || '').toLowerCase();
    const details = (alert.details || '').toLowerCase();
    const method = (alert.detection_method || '').toLowerCase();

    // 1. Decoy Honeypot Trap (Port 2222, 8088, 8888, 9090)
    if (details.includes('decoy') || details.includes('honeypot') || type.includes('decoy')) {
        return {
            sigId: 'SIG-1004',
            mitre: 'T1046',
            tactic: 'Defense Deception',
            name: 'Java 21 Loom Decoy Honeypot Trap',
            icon: '🪤'
        };
    }

    // 2. Flow Entropy & Volumetric ML Anomaly (Isolation Forest)
    if (method === 'ml' || details.includes('entropy') || details.includes('anomaly') || type.includes('anomaly')) {
        return {
            sigId: 'SIG-1005',
            mitre: 'T1071',
            tactic: 'C2 / Flow Entropy Anomaly',
            name: 'Isolation Forest Flow Entropy & Volumetric Anomaly',
            icon: '🧠'
        };
    }

    // 3. Port Scan / Reconnaissance Sweep
    if (type.includes('port_scan') || type.includes('port-scan') || type.includes('scan') || details.includes('scan') || details.includes('ports')) {
        return {
            sigId: 'SIG-1003',
            mitre: 'T1046',
            tactic: 'Reconnaissance',
            name: 'TCP Multi-Port Reconnaissance Sweep',
            icon: '🔍'
        };
    }

    // 4. Volumetric SYN Flood Surge
    if (type.includes('syn_flood') || type.includes('syn-flood') || type.includes('syn') || details.includes('syn') || details.includes('flood')) {
        return {
            sigId: 'SIG-1002',
            mitre: 'T1498.001',
            tactic: 'Impact / Denial of Service',
            name: 'TCP SYN Flood Volumetric Denial-of-Service',
            icon: '💥'
        };
    }

    // 5. Automated SSH / RDP Brute Force
    if (type.includes('brute_force') || type.includes('brute-force') || type.includes('brute') || details.includes('brute') || details.includes('authentication')) {
        return {
            sigId: 'SIG-1001',
            mitre: 'T1110.001',
            tactic: 'Credential Access',
            name: 'SSH Automated Brute Force Intrusion',
            icon: '🔑'
        };
    }

    // Default fallback to Network Reconnaissance
    return {
        sigId: 'SIG-1003',
        mitre: 'T1046',
        tactic: 'Network Telemetry',
        name: alert.attack_type ? alert.attack_type.toUpperCase().replace('_', ' ') : 'Network Anomaly',
        icon: '🛡️'
    };
}

function getAlertsForSignature(sig, alerts) {
    if (!alerts || alerts.length === 0) return [];
    return alerts.filter(a => {
        const mapped = mapAlertToMitre(a);
        return mapped && mapped.sigId === sig.id;
    });
}

function syncSignaturesWithAlerts(alerts = cachedAlerts) {
    const list = alerts || [];
    renderMitreVectorsGrid(list);
    renderMitreLiveIncidents(list);
    updateSignaturesKpis(list);
}

function updateSignaturesKpis(alerts = cachedAlerts) {
    const list = alerts || [];
    const totalHitsEl = document.getElementById('sigTotalHits');
    const triggeredVectorsEl = document.getElementById('sigTriggeredVectors');
    const vectorsCaptionEl = document.getElementById('sigVectorsCaption');
    const liveBadgeEl = document.getElementById('sigLiveBadge');

    let totalHits = list.length;
    let triggeredCount = 0;

    THREAT_SIGNATURES_REGISTRY.forEach(sig => {
        const matches = getAlertsForSignature(sig, list);
        if (matches.length > 0) {
            triggeredCount++;
        }
    });

    if (totalHitsEl) totalHitsEl.textContent = totalHits;
    if (triggeredVectorsEl) triggeredVectorsEl.textContent = triggeredCount;
    if (vectorsCaptionEl) {
        vectorsCaptionEl.textContent = triggeredCount > 0 
            ? `${triggeredCount} attack vector${triggeredCount > 1 ? 's' : ''} currently intercepted` 
            : 'All attack vectors idle';
        vectorsCaptionEl.style.color = triggeredCount > 0 ? '#ef4444' : 'var(--text-secondary)';
    }

    if (liveBadgeEl) {
        if (triggeredCount > 0) {
            liveBadgeEl.className = 'badge badge-critical';
            liveBadgeEl.textContent = `🚨 ${triggeredCount} ACTIVE ATTACK VECTORS • ${totalHits} INTERCEPTS`;
        } else {
            liveBadgeEl.className = 'badge badge-normal';
            liveBadgeEl.textContent = '● 5 VECTORS ARMORED • SYSTEM SECURE';
        }
    }
}

function renderMitreVectorsGrid(alerts = cachedAlerts) {
    const grid = document.getElementById('sigVectorsGrid');
    if (!grid) return;

    const list = alerts || [];

    // Filter to ONLY attack vectors that have actively been intercepted (hits > 0)
    const activeVectors = THREAT_SIGNATURES_REGISTRY.filter(v => getAlertsForSignature(v, list).length > 0);

    // If 0 active vectors (e.g. initial state or after clearing alerts), display clean empty state
    if (activeVectors.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 3.5rem 1.5rem; background: rgba(15, 23, 42, 0.45); border: 1px dashed var(--card-border); border-radius: 8px;">
                <div style="font-size: 2.2rem; margin-bottom: 0.5rem;">🛡️</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #10b981; letter-spacing: 0.02em;">ALL THREAT VECTORS ARMORED & SECURE</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.35rem; max-width: 550px; margin-left: auto; margin-right: auto; line-height: 1.5;">
                    No active threat vectors detected. When attacks or probes hit the platform (e.g. honeypot probe, port scan, SYN flood), only the intercepted vector cards will appear here dynamically.
                </div>
            </div>
        `;
        return;
    }

    // Only render the cards for vectors that are ACTUALLY active / intercepted
    grid.innerHTML = activeVectors.map(v => {
        const matches = getAlertsForSignature(v, list);
        const hits = matches.length;
        const lastAlert = matches[0];
        let lastAttacker = lastAlert ? (lastAlert.src_ip || '0.0.0.0') : '0.0.0.0';
        if (lastAttacker === '0:0:0:0:0:0:0:1' || lastAttacker === '::1') lastAttacker = '127.0.0.1';
        let lastTarget = lastAlert ? (lastAlert.dst_ip || '10.0.0.1') : '10.0.0.1';
        if (lastTarget === '0:0:0:0:0:0:0:1' || lastTarget === '::1') lastTarget = '127.0.0.1';
        const lastTime = lastAlert && lastAlert.timestamp ? new Date(lastAlert.timestamp).toLocaleTimeString() : 'Just now';

        let tactic = 'Initial Access';
        let icon = '🛡️';
        if (v.id === 'SIG-1001') { tactic = 'Credential Access'; icon = '🔑'; }
        else if (v.id === 'SIG-1002') { tactic = 'Impact / Denial of Service'; icon = '💥'; }
        else if (v.id === 'SIG-1003') { tactic = 'Reconnaissance'; icon = '🔍'; }
        else if (v.id === 'SIG-1004') { tactic = 'Defense Deception'; icon = '🪤'; }
        else if (v.id === 'SIG-1005') { tactic = 'C2 / Flow Entropy Anomaly'; icon = '🧠'; }

        return `
            <div class="sig-vector-card active-attack">
                <div class="sig-vector-header">
                    <div>
                        <span style="font-size: 0.7rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase;">${icon} ${tactic}</span>
                        <div class="sig-vector-title">${escapeHtml(v.name)}</div>
                        <div class="sig-vector-meta">${escapeHtml(v.id)} • MITRE ${escapeHtml(v.mitre)} • ${escapeHtml(v.cve)}</div>
                    </div>
                    <span class="badge badge-critical" style="font-size: 0.68rem;">
                        [ACTIVE • ${hits} HITS]
                    </span>
                </div>
                <div class="sig-vector-body">
                    ${escapeHtml(v.desc)}
                </div>
                <div style="font-size: 0.72rem; display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.3); padding: 6px 10px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.3);">
                    <span style="color: var(--text-muted);">🚨 Ingress Telemetry:</span>
                    <strong style="color: #ef4444; font-family: var(--font-mono);">
                        ${escapeHtml(lastAttacker)} ➔ ${escapeHtml(lastTarget)} (${escapeHtml(lastTime)})
                    </strong>
                </div>
                <div class="sig-vector-footer" style="margin-top: 0.6rem;">
                    <span class="badge ${v.engine.includes('ML') ? 'badge-method-ml' : 'badge-method-rule'}" style="font-size: 0.68rem;">${escapeHtml(v.engine)}</span>
                    <div>
                        <button class="btn" onclick="openSignatureModal('${v.id}')" style="padding: 0.2rem 0.6rem; font-size: 0.7rem;">Inspect Vector</button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function renderMitreLiveIncidents(alerts = cachedAlerts) {
    const tbody = document.getElementById('mitreLiveIncidentsTable');
    const badge = document.getElementById('mitreInterceptsBadge');
    if (!tbody) return;

    const list = alerts || [];
    if (badge) {
        badge.textContent = `${list.length} Incident${list.length === 1 ? '' : 's'} Recorded`;
        badge.className = list.length > 0 ? 'badge badge-critical' : 'badge badge-normal';
    }

    if (list.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 3rem 0; font-size: 0.85rem;">
                    🛡️ All threat vectors clear. 0 active intrusions recorded. Listening for incoming network traffic...
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = list.map(a => {
        const mapped = mapAlertToMitre(a);
        const safeSev = escapeHtml((a.severity || 'high').toLowerCase());
        const timeFormatted = a.timestamp ? escapeHtml(new Date(a.timestamp).toLocaleTimeString()) : 'Just now';
        let safeSrc = escapeHtml(a.src_ip || '0.0.0.0');
        if (safeSrc === '0:0:0:0:0:0:0:1' || safeSrc === '::1') safeSrc = '127.0.0.1';
        let safeDst = escapeHtml(a.dst_ip || '10.0.0.1');
        if (safeDst === '0:0:0:0:0:0:0:1' || safeDst === '::1') safeDst = '127.0.0.1';
        const safeDetails = escapeHtml(a.details || 'Network attack interception recorded.');
        const confPct = Math.round((a.confidence || 0.95) * 100);
        const methodBadge = (a.detection_method || '').toLowerCase() === 'ml'
            ? `<span class="badge badge-method-ml">🧠 ML</span>`
            : `<span class="badge badge-method-rule">⚙️ RULE</span>`;

        return `
            <tr>
                <td><span class="badge badge-${safeSev}">[${safeSev.toUpperCase()}]</span></td>
                <td style="font-family: monospace; font-size: 0.78rem;">${timeFormatted}</td>
                <td><strong style="color: #a855f7; font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(mapped.mitre)}</strong></td>
                <td><span style="font-weight: 600;">${mapped.icon} ${escapeHtml(mapped.name)}</span></td>
                <td><span class="ip-badge-src" style="font-family: monospace; font-size: 0.78rem;">${safeSrc}</span></td>
                <td><span class="ip-badge-dst" style="font-family: monospace; font-size: 0.78rem;">${safeDst}</span></td>
                <td>${methodBadge}</td>
                <td><span style="color: #10b981; font-weight: 700;">${confPct}%</span></td>
                <td style="font-size: 0.75rem; color: var(--text-secondary); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${safeDetails}">
                    ${safeDetails}
                </td>
            </tr>
        `;
    }).join('');
}

function openSignatureModal(sigId) {
    const v = THREAT_SIGNATURES_REGISTRY.find(x => x.id === sigId || x.cve === sigId) || THREAT_SIGNATURES_REGISTRY[0];
    const modalTitle = document.getElementById('modalSigTitle');
    const modalScore = document.getElementById('modalSigScore');
    const modalSev = document.getElementById('modalSigSev');
    const modalMethod = document.getElementById('modalSigMethod');
    const modalLink = document.getElementById('modalSigLink');
    const modalSummary = document.getElementById('modalSigSummary');
    const modalRuleLogic = document.getElementById('modalSigRuleLogic');
    const modalNodes = document.getElementById('modalSigNodes');

    const matches = getAlertsForSignature(v, cachedAlerts);

    if (modalTitle) modalTitle.textContent = `${v.id} • ${v.name}`;
    if (modalScore) modalScore.textContent = v.score.toFixed(1);
    if (modalSev) {
        modalSev.className = `badge badge-${v.sev}`;
        modalSev.textContent = `[${v.sev.toUpperCase()}]`;
    }
    if (modalMethod) {
        modalMethod.textContent = v.engine;
        modalMethod.className = `badge ${v.engine.includes('ML') ? 'badge-method-ml' : 'badge-method-rule'}`;
    }
    if (modalLink) {
        modalLink.href = v.advisory;
        modalLink.textContent = `${v.cve} (MITRE ${v.mitre}) Reference ↗`;
    }
    if (modalSummary) {
        modalSummary.textContent = v.desc;
    }
    if (modalRuleLogic) {
        modalRuleLogic.textContent = v.ruleLogic;
    }
    if (modalNodes) {
        if (matches.length > 0) {
            const first = matches[0];
            const src = first.src_ip || '0.0.0.0';
            const dst = first.dst_ip || '10.0.0.1';
            modalNodes.textContent = `${src} (Active Ingress) ➔ ${dst} (${matches.length} Interceptions Logged)`;
            modalNodes.style.color = '#ef4444';
        } else {
            modalNodes.textContent = 'No active intrusions detected • Standing By (Armored)';
            modalNodes.style.color = '#10b981';
        }
    }

    const modal = document.getElementById('signatureDetailModal');
    if (modal) modal.style.display = 'flex';
}

function closeSignatureModal() {
    const modal = document.getElementById('signatureDetailModal');
    if (modal) modal.style.display = 'none';
}

async function simulateFromRegistry(type) {
    if (!type) return;
    switchView('view-live-soc');
    await triggerAttack(type);
}

function downloadThreatReportCSV() {
    const alerts = cachedAlerts || [];
    const headers = [
        "MITRE Vector ID",
        "CVE / Reference",
        "MITRE Technique",
        "Attack Vector Title",
        "Target Protocol",
        "Detection Engine",
        "CVSS Score",
        "Severity",
        "Active Hits",
        "Defense Status",
        "Last Attacker IP",
        "Target Asset",
        "Detection Rule Logic"
    ];

    const rows = THREAT_SIGNATURES_REGISTRY.map(sig => {
        const matches = getAlertsForSignature(sig, alerts);
        const hits = matches.length;
        const lastAlert = matches[0];
        const lastIp = lastAlert ? (lastAlert.src_ip || 'None') : 'None';
        const target = lastAlert ? (lastAlert.dst_ip || '10.0.0.1') : 'Internal Network';
        const status = hits > 0 ? `TRIGGERED (${hits} hits)` : 'ARMED (0 hits)';

        return [
            `"${sig.id}"`,
            `"${sig.cve}"`,
            `"${sig.mitre}"`,
            `"${sig.name.replace(/"/g, '""')}"`,
            `"${sig.proto}"`,
            `"${sig.engine}"`,
            `"${sig.score}"`,
            `"${sig.sev.toUpperCase()}"`,
            `"${hits}"`,
            `"${status}"`,
            `"${lastIp}"`,
            `"${target.replace(/"/g, '""')}"`,
            `"${sig.ruleLogic.replace(/"/g, '""')}"`
        ].join(',');
    });

    let csvContent = "data:text/csv;charset=utf-8," + [
        "# NetSentinel NSM Platform - MITRE ATTACK Threat Vectors Coverage Report",
        headers.join(','),
        ...rows
    ].join('\n');

    if (alerts.length > 0) {
        csvContent += "\n\n# ACTUALLY INTERCEPTED INCIDENT LOG\nTimestamp,MITRE Technique,Attack Vector,Severity,Source IP,Destination IP,Engine,Confidence,Details\n";
        const incidentRows = alerts.map(a => {
            const mapped = mapAlertToMitre(a);
            return [
                `"${a.timestamp || new Date().toISOString()}"`,
                `"${mapped.mitre}"`,
                `"${mapped.name.replace(/"/g, '""')}"`,
                `"${(a.severity || 'high').toUpperCase()}"`,
                `"${a.src_ip || '0.0.0.0'}"`,
                `"${a.dst_ip || '10.0.0.1'}"`,
                `"${(a.detection_method || 'rule').toUpperCase()}"`,
                `"${Math.round((a.confidence || 0.95) * 100)}%"`,
                `"${(a.details || '').replace(/"/g, '""')}"`
            ].join(',');
        });
        csvContent += incidentRows.join('\n');
    }

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `NetSentinel_MITRE_ATTACK_Report_${timestamp}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function downloadThreatReportJSON() {
    const alerts = cachedAlerts || [];
    const report = {
        platform: "NetSentinel NSM Platform",
        reportType: "MITRE ATTACK Threat Vectors Coverage & Interception Audit",
        generatedAt: new Date().toISOString(),
        auditor: "NetSentinel SOC Administrator",
        summary: {
            totalRegisteredVectors: THREAT_SIGNATURES_REGISTRY.length,
            activeTriggeredVectors: THREAT_SIGNATURES_REGISTRY.filter(s => getAlertsForSignature(s, alerts).length > 0).length,
            totalInterceptions: alerts.length,
            overallStatus: alerts.length > 0 ? "ELEVATED_THREAT_ACTIVITY" : "ALL_SECURE"
        },
        mitreVectors: THREAT_SIGNATURES_REGISTRY.map(sig => {
            const matches = getAlertsForSignature(sig, alerts);
            return {
                id: sig.id,
                cve: sig.cve,
                mitreTechnique: sig.mitre,
                name: sig.name,
                description: sig.desc,
                protocol: sig.proto,
                engine: sig.engine,
                cvssScore: sig.score,
                severity: sig.sev,
                interceptHits: matches.length,
                status: matches.length > 0 ? "TRIGGERED" : "ARMED",
                latestAttacker: matches.length > 0 ? (matches[0].src_ip || null) : null
            };
        }),
        interceptedIncidents: alerts.map(a => {
            const mapped = mapAlertToMitre(a);
            return {
                timestamp: a.timestamp,
                mitreTechnique: mapped.mitre,
                attackVector: mapped.name,
                severity: a.severity,
                sourceIp: a.src_ip,
                destinationIp: a.dst_ip,
                detectionEngine: a.detection_method,
                confidence: a.confidence,
                details: a.details
            };
        })
    };

    const jsonString = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    link.setAttribute("href", jsonString);
    link.setAttribute("download", `NetSentinel_MITRE_ATTACK_Audit_${timestamp}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// ==========================================
// VIEW 5: OFFICIAL LEAFLET WORLD THREAT MAP & TELEMETRY
// ==========================================
let threatMapFilter = 'ALL';
let wanTelemetryHistory = [];
let wanCanvasAnimId = null;

let leafletThreatMap = null;
let leafletMarkersLayer = null;
let leafletArcsLayer = null;

const SENSOR_GATEWAYS = [
    { id: 'gw-us-east', name: 'US-East Core Gateway', ip: '10.0.0.1', lat: 38.9072, lng: -77.0369, region: 'North America (Washington DC)', role: 'Enterprise Core Transit' },
    { id: 'gw-london', name: 'London Edge Proxy', ip: '10.0.0.2', lat: 51.5074, lng: -0.1278, region: 'Europe (London)', role: 'WAN Ingress Proxy' },
    { id: 'gw-frankfurt', name: 'Frankfurt Datacenter', ip: '10.0.0.3', lat: 50.1109, lng: 8.6821, region: 'Europe (Frankfurt)', role: 'Security Gateway' },
    { id: 'gw-singapore', name: 'Singapore Honeypot', ip: '10.0.0.4', lat: 1.3521, lng: 103.8198, region: 'Asia-Pacific (Singapore)', role: 'Loom Decoy Listener (Ports 2222, 8088)' },
    { id: 'gw-tokyo', name: 'Tokyo Monitoring Sensor', ip: '10.0.0.5', lat: 35.6762, lng: 139.6503, region: 'Asia-Pacific (Tokyo)', role: 'Sensor Hub' },
    { id: 'gw-sydney', name: 'Sydney Branch Node', ip: '10.0.0.6', lat: -33.8688, lng: 151.2093, region: 'Oceania (Sydney)', role: 'Branch Edge Node' }
];

const ADVERSARY_ORIGIN_MAP = {
    '192.168.1.77': { lat: 40.7128, lng: -74.0060, location: 'North America (New York Edge)', flag: '🇺🇸', asn: 'AS16509 AWS Ingress' },
    '192.168.1.99': { lat: 37.5665, lng: 126.9780, location: 'East Asia (Seoul Transit)', flag: '🇰🇷', asn: 'AS24940 Edge Transit' },
    '192.168.1.50': { lat: 52.5200, lng: 13.4050, location: 'Western Europe (Berlin IX)', flag: '🇩🇪', asn: 'AS13335 CDN Ingress' },
    '0.0.0.0': { lat: 30.0444, lng: 31.2357, location: 'Simulated WAN Decoy Stream', flag: '🌐', asn: 'AS-DECOY-LOCAL' }
};

let threatGlobe = null;
let currentMapMode = 'globe'; // 'globe' (3D WebGL) or '2d' (Leaflet)
let isGlobeAutoRotating = true;

function initGlobeMap() {
    if (threatGlobe || typeof Globe === 'undefined') return;

    const mapContainer = document.getElementById('globeThreatMap');
    if (!mapContainer) return;

    try {
        const width = mapContainer.clientWidth || 600;
        const height = 440;

        threatGlobe = Globe()(mapContainer)
            .globeImageUrl('img/earth-night.jpg')
            .backgroundColor('rgba(0, 0, 0, 0)')
            .showAtmosphere(true)
            .atmosphereColor('#38bdf8')
            .atmosphereAltitude(0.18)
            .width(width)
            .height(height);

        const controls = threatGlobe.controls();
        if (controls) {
            controls.autoRotate = isGlobeAutoRotating;
            controls.autoRotateSpeed = 0.55;
            controls.enableDamping = true;
            controls.dampingFactor = 0.08;
            controls.minDistance = 140;
            controls.maxDistance = 550;
        }

        // Default perspective viewing global continents
        threatGlobe.pointOfView({ lat: 22, lng: 12, altitude: 2.2 });

        renderThreatGlobeData();
    } catch (e) {
        console.error('Failed to initialize Globe.gl:', e);
    }
}

function initLeafletMap() {
    if (leafletThreatMap || typeof L === 'undefined') return;

    const mapContainer = document.getElementById('leafletThreatMap');
    if (!mapContainer) return;

    try {
        leafletThreatMap = L.map('leafletThreatMap', {
            center: [25, 12],
            zoom: 2,
            minZoom: 2,
            maxZoom: 8,
            maxBounds: [[-85, -180], [85, 180]],
            maxBoundsViscosity: 1.0,
            worldCopyJump: false,
            zoomControl: true,
            attributionControl: true
        });

        // Esri World Dark Gray Canvas (official enterprise SOC dark cartography with noWrap)
        L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
            attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
            maxZoom: 16,
            noWrap: true,
            bounds: [[-85, -180], [85, 180]]
        }).addTo(leafletThreatMap);

        // Esri World Dark Gray Reference (subtle dark borders & labels)
        L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
            maxZoom: 16,
            noWrap: true,
            bounds: [[-85, -180], [85, 180]]
        }).addTo(leafletThreatMap);

        leafletArcsLayer = L.layerGroup().addTo(leafletThreatMap);
        leafletMarkersLayer = L.layerGroup().addTo(leafletThreatMap);

        renderThreatMap();
    } catch (e) {
        console.error('Failed to initialize Leaflet map:', e);
    }
}

function getCurvedPoints(lat1, lng1, lat2, lng2) {
    const points = [];
    const numPoints = 25;
    const midLat = (lat1 + lat2) / 2;
    const midLng = (lng1 + lng2) / 2;

    const dLat = lat2 - lat1;
    const dLng = lng2 - lng1;
    const dist = Math.sqrt(dLat * dLat + dLng * dLng);
    const bulge = Math.min(22, Math.max(8, dist * 0.22));

    const ctrlLat = midLat + bulge;
    const ctrlLng = midLng;

    for (let i = 0; i <= numPoints; i++) {
        const t = i / numPoints;
        const lat = Math.pow(1 - t, 2) * lat1 + 2 * (1 - t) * t * ctrlLat + Math.pow(t, 2) * lat2;
        const lng = Math.pow(1 - t, 2) * lng1 + 2 * (1 - t) * t * ctrlLng + Math.pow(t, 2) * lng2;
        points.push([lat, lng]);
    }
    return points;
}

function setThreatMapFilter(filter) {
    threatMapFilter = filter;
    const group = document.getElementById('threatMapFilterGroup');
    if (group) {
        group.querySelectorAll('.threat-filter-btn').forEach(btn => {
            const isMatch = (filter === 'ALL' && btn.textContent.includes('ALL')) ||
                            (filter === 'port_scan' && btn.textContent.includes('RECONNAISSANCE')) ||
                            (filter === 'syn_flood' && btn.textContent.includes('DOS')) ||
                            (filter === 'brute_force' && btn.textContent.includes('BRUTE'));
            btn.classList.toggle('active', isMatch);
        });
    }
    renderThreatMap();
}

function renderThreatMap() {
    const liveBadge = document.getElementById('threatMapLiveBadge');
    const interceptCount = document.getElementById('mapInterceptCount');
    const interceptList = document.getElementById('mapInterceptList');
    const regionalDensity = document.getElementById('mapRegionalDensity');

    // Ensure active map initialized based on current projection mode
    if (currentMapMode === 'globe') {
        if (!threatGlobe && typeof Globe !== 'undefined') {
            initGlobeMap();
        } else if (threatGlobe) {
            renderThreatGlobeData();
        }
    } else {
        if (!leafletThreatMap && typeof L !== 'undefined') {
            initLeafletMap();
        }
    }

    // Filter active alerts
    let activeAlerts = (cachedAlerts || []).slice(0, 15);
    if (threatMapFilter !== 'ALL') {
        activeAlerts = activeAlerts.filter(a => (a.attack_type || '').toLowerCase() === threatMapFilter.toLowerCase());
    }

    // If Leaflet is active in 2D mode, render markers & curved trajectories
    if (currentMapMode === '2d' && leafletThreatMap && leafletMarkersLayer && leafletArcsLayer) {
        leafletMarkersLayer.clearLayers();
        leafletArcsLayer.clearLayers();

        const attackedGateways = new Set();
        activeAlerts.forEach(a => {
            const dst = a.dst_ip || a.destIp || '10.0.0.1';
            if (dst.startsWith('10.0.0.')) attackedGateways.add(dst);
            else attackedGateways.add('10.0.0.1');
        });

        // 1. Render Monitored Sensor Gateways
        SENSOR_GATEWAYS.forEach(gw => {
            const isTargeted = attackedGateways.has(gw.ip) || (attackedGateways.size > 0 && gw.ip === '10.0.0.1');
            const color = isTargeted ? '#ef4444' : '#10b981';
            const pulseColor = isTargeted ? 'rgba(239, 68, 68, 0.45)' : 'rgba(16, 185, 129, 0.35)';

            const icon = L.divIcon({
                className: 'custom-map-beacon',
                html: `
                    <div style="position: relative; width: 22px; height: 22px; display: flex; align-items: center; justify-content: center;">
                        <div style="position: absolute; width: 100%; height: 100%; border-radius: 50%; background: ${pulseColor}; animation: mapPulse 2s infinite;"></div>
                        <div style="width: 10px; height: 10px; border-radius: 50%; background: ${color}; border: 2px solid #ffffff; box-shadow: 0 0 10px ${color};"></div>
                    </div>
                `,
                iconSize: [22, 22],
                iconAnchor: [11, 11]
            });

            const marker = L.marker([gw.lat, gw.lng], { icon: icon });
            marker.bindPopup(`
                <div style="font-family: var(--font-sans); color: #f8fafc; font-size: 0.8rem; line-height: 1.45;">
                    <strong style="color: #38bdf8; font-size: 0.86rem;">${escapeHtml(gw.name)}</strong><br>
                    <span style="color: #94a3b8; font-family: var(--font-mono); font-size: 0.72rem;">IP: ${escapeHtml(gw.ip)} (${escapeHtml(gw.region)})</span><br>
                    <span style="color: #cbd5e1; font-size: 0.74rem;">Role: ${escapeHtml(gw.role)}</span><br>
                    <div style="margin-top: 4px; font-weight: 700; color: ${isTargeted ? '#ef4444' : '#10b981'};">
                        ${isTargeted ? '🚨 ACTIVE INGRESS TARGET' : '● OPERATIONAL • ALL SECURE'}
                    </div>
                </div>
            `);
            marker.addTo(leafletMarkersLayer);
        });

        // 2. Render Trajectories and Attacker Origin Markers
        const renderedOrigins = new Set();
        activeAlerts.forEach(a => {
            const srcIp = a.src_ip || a.sourceIp || '192.168.1.77';
            const origin = ADVERSARY_ORIGIN_MAP[srcIp] || {
                lat: 25.0 + (((srcIp.split('.').reduce((acc, v) => acc + parseInt(v || 0), 0) * 17) % 60) - 30),
                lng: ((srcIp.split('.').reduce((acc, v) => acc + parseInt(v || 0), 0) * 31) % 320) - 160,
                location: 'External Ingress',
                flag: '🌐',
                asn: 'AS-Transit'
            };

            const targetGw = SENSOR_GATEWAYS[0]; // Primary Gateway (US-East Core)
            const attackType = (a.attack_type || '').toLowerCase();
            let strokeColor = '#ef4444'; // Red for Brute Force
            if (attackType === 'syn_flood') strokeColor = '#f59e0b'; // Amber for SYN Flood
            else if (attackType === 'port_scan') strokeColor = '#06b6d4'; // Cyan for Port Scan

            // Curved trajectory points
            const curvePoints = getCurvedPoints(origin.lat, origin.lng, targetGw.lat, targetGw.lng);
            const polyline = L.polyline(curvePoints, {
                color: strokeColor,
                weight: 2.8,
                dashArray: '8, 8',
                opacity: 0.9,
                className: 'leaflet-attack-arc'
            });
            polyline.bindPopup(`
                <div style="font-size: 0.78rem;">
                    <strong style="color: ${strokeColor};">${attackType.toUpperCase().replace('_', ' ')}</strong><br>
                    <span>${escapeHtml(srcIp)} ➔ ${escapeHtml(targetGw.ip)}</span>
                </div>
            `);
            polyline.addTo(leafletArcsLayer);

            // Attacker origin marker (render once per attacker)
            if (!renderedOrigins.has(srcIp)) {
                renderedOrigins.add(srcIp);
                const advIcon = L.divIcon({
                    className: 'custom-adv-beacon',
                    html: `
                        <div style="position: relative; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center;">
                            <div style="position: absolute; width: 100%; height: 100%; border-radius: 50%; background: ${strokeColor}; opacity: 0.5; animation: mapPulse 1.5s infinite;"></div>
                            <div style="width: 8px; height: 8px; border-radius: 50%; background: ${strokeColor}; border: 2px solid #ffffff;"></div>
                        </div>
                    `,
                    iconSize: [20, 20],
                    iconAnchor: [10, 10]
                });

                const advMarker = L.marker([origin.lat, origin.lng], { icon: advIcon });
                advMarker.bindPopup(`
                    <div style="font-size: 0.8rem; line-height: 1.4;">
                        <strong>${origin.flag} ${escapeHtml(origin.location)}</strong><br>
                        <span style="font-family: var(--font-mono); color: #ef4444;">IP: ${escapeHtml(srcIp)}</span><br>
                        <span style="color: #94a3b8; font-size: 0.72rem;">ASN: ${escapeHtml(origin.asn)}</span>
                    </div>
                `);
                advMarker.addTo(leafletMarkersLayer);
            }
        });
    }

    // Update Live Status Badge
    if (liveBadge) {
        if (activeAlerts.length > 0) {
            liveBadge.className = 'badge badge-critical';
            liveBadge.textContent = `🚨 ${activeAlerts.length} ACTIVE INGRESS INTERCEPTS`;
        } else {
            liveBadge.className = 'badge badge-normal';
            liveBadge.textContent = '● 6 SENSORS ACTIVE • ALL SECURE';
        }
    }

    // Update Sidebar Intercepts List
    if (interceptCount && interceptList) {
        if (activeAlerts.length === 0) {
            interceptCount.textContent = '0 Active';
            interceptCount.className = 'badge badge-normal';
            interceptList.innerHTML = `
                <div style="text-align: center; color: var(--text-muted); padding: 3rem 0.5rem; font-size: 0.8rem; line-height: 1.5;">
                    🛡️ No anomalous ingress vectors detected across global sensors. System operational.
                </div>`;
        } else {
            interceptCount.textContent = `${activeAlerts.length} Active`;
            interceptCount.className = 'badge badge-critical';
            interceptList.innerHTML = activeAlerts.slice(0, 6).map(a => {
                const src = a.src_ip || a.sourceIp || '192.168.1.77';
                const meta = ADVERSARY_ORIGIN_MAP[src] || { location: 'External Ingress', flag: '🌐', asn: 'AS-Transit', lat: 25, lng: -40 };
                const at = (a.attack_type || 'ANOMALY').toUpperCase().replace('_', ' ');
                const time = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'Just now';
                const sev = (a.severity || 'low').toLowerCase();
                return `
                    <div class="threat-map-intercept-item" style="cursor: pointer;" onclick="focusLeafletThreat('${src}')" title="Click to locate on world map">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                            <strong>${meta.flag} ${escapeHtml(meta.location)}</strong>
                            <span class="badge badge-${sev}">[${sev.toUpperCase()}]</span>
                        </div>
                        <div style="font-family: var(--font-mono); font-size: 0.73rem; color: var(--accent-blue);">
                            ${escapeHtml(src)} ➔ ${escapeHtml(a.dst_ip || '10.0.0.1')}
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-top: 3px; font-size: 0.68rem; color: var(--text-muted);">
                            <span>${escapeHtml(at)}</span>
                            <span>${escapeHtml(time)}</span>
                        </div>
                    </div>`;
            }).join('');
        }
    }

    // Update Regional Density Breakdown
    if (regionalDensity) {
        if (activeAlerts.length === 0) {
            regionalDensity.innerHTML = `
                <div style="display: flex; justify-content: space-between;">
                    <span>North America (US-East)</span>
                    <span style="color: #10b981;">● Optimal (0 threats)</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span>Europe (London/Frankfurt)</span>
                    <span style="color: #10b981;">● Optimal (0 threats)</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span>Asia-Pacific (Singapore)</span>
                    <span style="color: #10b981;">● Decoy Armed (0 threats)</span>
                </div>`;
        } else {
            regionalDensity.innerHTML = `
                <div style="display: flex; justify-content: space-between;">
                    <span>North America (US-East)</span>
                    <span style="color: #ef4444; font-weight: 700;">● Active Threat Vector</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span>Western Europe</span>
                    <span style="color: #f59e0b; font-weight: 700;">● Ingress Telemetry Active</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span>Asia-Pacific (Singapore)</span>
                    <span style="color: #38bdf8;">● Decoy Listeners Ready</span>
                </div>`;
        }
    }
}

function renderThreatGlobeData() {
    if (!threatGlobe) return;

    // Filter active alerts
    let activeAlerts = (cachedAlerts || []).slice(0, 15);
    if (threatMapFilter !== 'ALL') {
        activeAlerts = activeAlerts.filter(a => (a.attack_type || '').toLowerCase() === threatMapFilter.toLowerCase());
    }

    const attackedGateways = new Set();
    activeAlerts.forEach(a => {
        const dst = a.dst_ip || a.destIp || '10.0.0.1';
        if (dst.startsWith('10.0.0.')) attackedGateways.add(dst);
        else attackedGateways.add('10.0.0.1');
    });

    // 1. Build Sensor Hub Labels
    const labels = [];
    SENSOR_GATEWAYS.forEach(gw => {
        const isTargeted = attackedGateways.has(gw.ip) || (attackedGateways.size > 0 && gw.ip === '10.0.0.1');
        labels.push({
            lat: gw.lat,
            lng: gw.lng,
            text: gw.name.split(' ')[0],
            color: isTargeted ? '#ef4444' : '#38bdf8',
            size: 1.1,
            dotRadius: 0.55,
            tooltip: `
                <div style="font-family: var(--font-sans); color: #f8fafc; font-size: 0.78rem; line-height: 1.45;">
                    <strong style="color: #38bdf8; font-size: 0.84rem;">${escapeHtml(gw.name)}</strong><br>
                    <span style="color: #94a3b8; font-family: var(--font-mono); font-size: 0.7rem;">IP: ${escapeHtml(gw.ip)} (${escapeHtml(gw.region)})</span><br>
                    <span style="color: #cbd5e1; font-size: 0.72rem;">Role: ${escapeHtml(gw.role)}</span><br>
                    <div style="margin-top: 4px; font-weight: 700; color: ${isTargeted ? '#ef4444' : '#10b981'};">
                        ${isTargeted ? '🚨 ACTIVE INGRESS TARGET' : '● OPERATIONAL • ALL SECURE'}
                    </div>
                </div>
            `
        });
    });

    // 2. Build 3D Arcs & Adversary Origin Labels
    const arcs = [];
    const renderedOrigins = new Set();
    const primaryGw = SENSOR_GATEWAYS[0];

    activeAlerts.forEach((a, idx) => {
        const srcIp = a.src_ip || a.sourceIp || '192.168.1.77';
        const origin = ADVERSARY_ORIGIN_MAP[srcIp] || {
            lat: 25.0 + (((srcIp.split('.').reduce((acc, v) => acc + parseInt(v || 0), 0) * 17) % 60) - 30),
            lng: ((srcIp.split('.').reduce((acc, v) => acc + parseInt(v || 0), 0) * 31) % 320) - 160,
            location: 'External Ingress',
            flag: '🌐',
            asn: 'AS-Transit'
        };

        const attackType = (a.attack_type || 'anomaly').toLowerCase();
        let arcColors = ['#ef4444', '#f59e0b'];
        if (attackType === 'syn_flood') arcColors = ['#f59e0b', '#fbbf24'];
        else if (attackType === 'port_scan') arcColors = ['#06b6d4', '#38bdf8'];

        arcs.push({
            startLat: origin.lat,
            startLng: origin.lng,
            endLat: primaryGw.lat,
            endLng: primaryGw.lng,
            color: arcColors,
            altitude: 0.22 + (idx % 3) * 0.08,
            stroke: 1.6,
            dashLength: 0.45,
            dashGap: 2.2,
            initialGap: idx * 0.35,
            label: `
                <div style="font-family: var(--font-sans); color: #f8fafc; font-size: 0.75rem;">
                    <strong style="color: ${arcColors[0]};">${attackType.toUpperCase().replace('_', ' ')}</strong><br>
                    <span>${escapeHtml(srcIp)} (${origin.location}) ➔ ${escapeHtml(primaryGw.ip)}</span>
                </div>
            `
        });

        if (!renderedOrigins.has(srcIp)) {
            renderedOrigins.add(srcIp);
            labels.push({
                lat: origin.lat,
                lng: origin.lng,
                text: srcIp,
                color: '#ef4444',
                size: 0.95,
                dotRadius: 0.5,
                tooltip: `
                    <div style="font-family: var(--font-sans); color: #f8fafc; font-size: 0.78rem; line-height: 1.4;">
                        <strong>${origin.flag} ${escapeHtml(origin.location)}</strong><br>
                        <span style="font-family: var(--font-mono); color: #ef4444; font-size: 0.72rem;">IP: ${escapeHtml(srcIp)}</span><br>
                        <span style="color: #94a3b8; font-size: 0.7rem;">ASN: ${escapeHtml(origin.asn)}</span>
                    </div>
                `
            });
        }
    });

    // 3. Build Pulsing Target Rings
    const rings = [];
    SENSOR_GATEWAYS.forEach(gw => {
        const isTargeted = attackedGateways.has(gw.ip) || (attackedGateways.size > 0 && gw.ip === '10.0.0.1');
        if (isTargeted) {
            rings.push({
                lat: gw.lat,
                lng: gw.lng,
                color: '#ef4444',
                maxRadius: 5.5,
                propagationSpeed: 2.2,
                repeatPeriod: 750
            });
        }
    });

    // Apply layers to 3D Globe
    threatGlobe
        .labelsData(labels)
        .labelLat(d => d.lat)
        .labelLng(d => d.lng)
        .labelText(d => d.text)
        .labelSize(d => d.size)
        .labelDotRadius(d => d.dotRadius)
        .labelColor(d => d.color)
        .labelResolution(2)
        .labelAltitude(0.015)
        .labelLabel(d => d.tooltip)
        .arcsData(arcs)
        .arcStartLat(d => d.startLat)
        .arcStartLng(d => d.startLng)
        .arcEndLat(d => d.endLat)
        .arcEndLng(d => d.endLng)
        .arcColor(d => d.color)
        .arcAltitude(d => d.altitude)
        .arcStroke(d => d.stroke)
        .arcDashLength(d => d.dashLength)
        .arcDashGap(d => d.dashGap)
        .arcDashInitialGap(d => d.initialGap)
        .arcDashAnimateTime(1800)
        .arcLabel(d => d.label)
        .ringsData(rings)
        .ringLat(d => d.lat)
        .ringLng(d => d.lng)
        .ringColor(d => d.color)
        .ringMaxRadius(d => d.maxRadius)
        .ringPropagationSpeed(d => d.propagationSpeed)
        .ringRepeatPeriod(d => d.repeatPeriod);
}

function setMapDisplayMode(mode) {
    currentMapMode = mode;
    const globeEl = document.getElementById('globeThreatMap');
    const leafletEl = document.getElementById('leafletThreatMap');
    const hud = document.getElementById('globeHudOverlay');
    const btnGlobe = document.getElementById('btnMapGlobe');
    const btnFlat = document.getElementById('btnMapFlat');

    if (btnGlobe) btnGlobe.classList.toggle('active', mode === 'globe');
    if (btnFlat) btnFlat.classList.toggle('active', mode === '2d');

    if (mode === 'globe') {
        if (globeEl) globeEl.style.display = 'block';
        if (leafletEl) leafletEl.style.display = 'none';
        if (hud) hud.style.display = 'flex';
        if (!threatGlobe) {
            initGlobeMap();
        } else {
            const w = globeEl ? globeEl.clientWidth : 600;
            if (w > 0) threatGlobe.width(w);
            renderThreatGlobeData();
        }
    } else {
        if (globeEl) globeEl.style.display = 'none';
        if (leafletEl) leafletEl.style.display = 'block';
        if (hud) hud.style.display = 'none';
        if (!leafletThreatMap) {
            initLeafletMap();
        } else {
            setTimeout(() => {
                try { leafletThreatMap.invalidateSize(); } catch (e) {}
                renderThreatMap();
            }, 60);
        }
    }
}

function updateGlobeSpinButton(isSpinning) {
    isGlobeAutoRotating = isSpinning;
    const btn = document.getElementById('btnGlobeRotate');
    const icon = document.getElementById('globeRotateIcon');
    if (btn) btn.classList.toggle('active', isSpinning);
    if (icon) icon.textContent = isSpinning ? '⏸' : '▶';
}

function toggleGlobeAutoRotate() {
    if (!threatGlobe || !threatGlobe.controls()) return;
    const nextState = !threatGlobe.controls().autoRotate;
    threatGlobe.controls().autoRotate = nextState;
    updateGlobeSpinButton(nextState);
}

function resetGlobeCamera() {
    if (threatGlobe) {
        threatGlobe.pointOfView({ lat: 22, lng: 12, altitude: 2.2 }, 1000);
    }
}

function focusThreatOnMap(srcIp) {
    const origin = ADVERSARY_ORIGIN_MAP[srcIp];
    if (!origin) return;

    if (currentMapMode === 'globe' && threatGlobe) {
        if (threatGlobe.controls()) {
            threatGlobe.controls().autoRotate = false;
            updateGlobeSpinButton(false);
        }
        threatGlobe.pointOfView({
            lat: origin.lat,
            lng: origin.lng,
            altitude: 1.55
        }, 1200);
    } else if (leafletThreatMap) {
        leafletThreatMap.flyTo([origin.lat, origin.lng], 4, { duration: 1.2 });
    }
}

function focusLeafletThreat(srcIp) {
    focusThreatOnMap(srcIp);
}

window.addEventListener('resize', () => {
    if (threatGlobe && currentMapMode === 'globe') {
        const c = document.getElementById('globeThreatMap');
        if (c && c.clientWidth > 0) threatGlobe.width(c.clientWidth);
    }
});

// ------------------------------------------
// LIVE ROLLING WAN INTERFACE CANVAS TELEMETRY
// ------------------------------------------
function initWanCanvas() {
    const canvas = document.getElementById('wanTelemetryCanvas');
    if (!canvas) return;

    // Initialize 35 history slots with base throughput
    if (wanTelemetryHistory.length === 0) {
        for (let i = 0; i < 35; i++) {
            wanTelemetryHistory.push({ pps: 2.0 + Math.random() * 1.5, discards: 0 });
        }
    }

    if (!wanCanvasAnimId) {
        renderWanTelemetryFrame();
    }
}

function renderWanTelemetryFrame() {
    const canvas = document.getElementById('wanTelemetryCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;

    if (w <= 0 || h <= 0) {
        wanCanvasAnimId = requestAnimationFrame(renderWanTelemetryFrame);
        return;
    }

    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
    }

    ctx.save();
    ctx.scale(dpr, dpr);

    // Dark screen background
    ctx.fillStyle = '#020617';
    ctx.fillRect(0, 0, w, h);

    // Subtle Grid Lines
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
    ctx.lineWidth = 1;
    for (let y = 25; y < h; y += 30) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    const data = wanTelemetryHistory;
    const len = data.length;
    if (len >= 2) {
        // Find max PPS to dynamically scale
        const maxPps = Math.max(25, ...data.map(d => d.pps));

        // 1. Throughput Gradient Area Chart (Cyan)
        ctx.beginPath();
        const step = w / (len - 1);
        ctx.moveTo(0, h);
        for (let i = 0; i < len; i++) {
            const val = data[i].pps;
            const y = h - (val / maxPps) * (h - 20) - 10;
            ctx.lineTo(i * step, y);
        }
        ctx.lineTo(w, h);
        ctx.closePath();

        const grad = ctx.createLinearGradient(0, 0, 0, h);
        grad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
        grad.addColorStop(1, 'rgba(6, 182, 212, 0.02)');
        ctx.fillStyle = grad;
        ctx.fill();

        // Throughput Stroke Line
        ctx.beginPath();
        for (let i = 0; i < len; i++) {
            const val = data[i].pps;
            const y = h - (val / maxPps) * (h - 20) - 10;
            if (i === 0) ctx.moveTo(0, y);
            else ctx.lineTo(i * step, y);
        }
        ctx.strokeStyle = '#06b6d4';
        ctx.lineWidth = 2;
        ctx.stroke();

        // 2. Discards Spike Line (Red)
        ctx.beginPath();
        for (let i = 0; i < len; i++) {
            const discards = data[i].discards;
            const y = h - (discards / 15) * (h * 0.45) - 6;
            if (i === 0) ctx.moveTo(0, y);
            else ctx.lineTo(i * step, y);
        }
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 1.8;
        ctx.stroke();
    }

    ctx.restore();
    wanCanvasAnimId = requestAnimationFrame(renderWanTelemetryFrame);
}

function updateWanStats() {
    const isUnderAttack = (cachedAlerts && cachedAlerts.length > 0);
    const newest = isUnderAttack ? cachedAlerts[0] : null;
    const now = Date.now();
    const isRecent = newest && (now - new Date(newest.timestamp).getTime() < 8000);

    // Compute live packet rate
    let activePps = currentPps > 0 ? currentPps : (2.0 + Math.random() * 1.5);
    let activeDiscards = 0;

    if (isRecent) {
        if (newest.attack_type === 'syn_flood') {
            activePps = 85.0 + Math.random() * 35.0;
            activeDiscards = 8.5 + Math.random() * 4.0;
        } else if (newest.attack_type === 'port_scan') {
            activePps = 45.0 + Math.random() * 20.0;
            activeDiscards = 3.2 + Math.random() * 2.0;
        } else if (newest.attack_type === 'brute_force') {
            activePps = 30.0 + Math.random() * 15.0;
            activeDiscards = 2.0 + Math.random() * 1.5;
        }
    }

    wanTelemetryHistory.push({ pps: activePps, discards: activeDiscards });
    if (wanTelemetryHistory.length > 35) wanTelemetryHistory.shift();

    const wanRx = document.getElementById('wanRxVal');
    const wanTx = document.getElementById('wanTxVal');
    if (wanRx) wanRx.textContent = `${activePps.toFixed(1)} pkts/s`;
    if (wanTx) wanTx.textContent = `${activeDiscards.toFixed(1)} pkts/s`;
}

// ------------------------------------------
// 100% DYNAMIC HARDWARE & SENSOR HEALTH DONUT
// ------------------------------------------
function updateSensorHealthDonut() {
    const list = currentNodesList && currentNodesList.length > 0 ? currentNodesList : [];
    const hasAlerts = cachedAlerts && cachedAlerts.length > 0;

    let critNodes = 0;
    let warnNodes = 0;
    let upNodes = 6;

    if (list.length > 0) {
        critNodes = list.filter(n => n.health === 'critical').length;
        warnNodes = list.filter(n => n.health === 'high' || n.health === 'medium').length;
        upNodes = Math.max(0, list.length - critNodes - warnNodes);
        if (upNodes === 0 && critNodes === 0 && warnNodes === 0) upNodes = 6;
    } else if (hasAlerts) {
        const critAlerts = cachedAlerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
        critNodes = critAlerts > 0 ? 1 : 0;
        warnNodes = (cachedAlerts.length > critAlerts) ? 1 : 0;
        upNodes = Math.max(0, 6 - critNodes - warnNodes);
    }

    const total = Math.max(1, critNodes + warnNodes + upNodes);
    const C = 238.76; // Circumference for r=38

    const greenLen = (upNodes / total) * C;
    const yellowLen = (warnNodes / total) * C;
    const redLen = (critNodes / total) * C;

    const segGreen = document.getElementById('sensorDonutGreen');
    const segYellow = document.getElementById('sensorDonutYellow');
    const segRed = document.getElementById('sensorDonutRed');

    if (segGreen) {
        segGreen.setAttribute('stroke-dasharray', `${greenLen} ${C}`);
        segGreen.setAttribute('stroke-dashoffset', '0');
    }
    if (segYellow) {
        segYellow.setAttribute('stroke-dasharray', `${yellowLen} ${C}`);
        segYellow.setAttribute('stroke-dashoffset', `-${greenLen}`);
    }
    if (segRed) {
        segRed.setAttribute('stroke-dasharray', `${redLen} ${C}`);
        segRed.setAttribute('stroke-dashoffset', `-${greenLen + yellowLen}`);
    }

    const txtUp = document.getElementById('sensorCountUp');
    const txtWarn = document.getElementById('sensorCountWarn');
    const txtCrit = document.getElementById('sensorCountCrit');
    const badge = document.getElementById('sensorHealthOverallBadge');

    if (txtUp) txtUp.textContent = `${upNodes} Nodes`;
    if (txtWarn) txtWarn.textContent = `${warnNodes} Nodes`;
    if (txtCrit) txtCrit.textContent = `${critNodes} Nodes`;

    if (badge) {
        if (critNodes > 0) {
            badge.className = 'badge badge-critical';
            badge.textContent = `HEALTH: CRITICAL ALARM (${critNodes} AFFECTED)`;
        } else if (warnNodes > 0) {
            badge.className = 'badge badge-high';
            badge.textContent = `HEALTH: WARNING STATE (${warnNodes} ANOMALIES)`;
        } else {
            badge.className = 'badge badge-normal';
            badge.textContent = 'HEALTH: 100% OPERATIONAL';
        }
    }
}

// ==========================================
// VIEW 6: SOLARWINDS INTERACTIVE FAQ SPLIT-PANE
// ==========================================
const FAQ_ITEMS = [
    {
        q: 'What is network security monitoring software?',
        a: `
            <p><strong>Network Security Monitoring (NSM)</strong> software is designed to detect and analyze activities that may indicate security issues, offering warnings that allow security operations (SOC) teams to act quickly and protect business infrastructure from network intrusions.</p>
            <p>By collecting metrics on client-server communications, encrypted traffic sessions, and port operations, NSM platforms identify potential cybersecurity threats in real time before damage occurs.</p>
        `
    },
    {
        q: 'What is the difference between network monitoring and network security monitoring?',
        a: `
            <p>Standard <strong>Network Monitoring</strong> focuses on performance, uptime, interface bandwidth, packet loss, and latency to ensure network availability.</p>
            <p><strong>Network Security Monitoring (NSM)</strong> focuses on threat discovery: analyzing payload patterns, detecting unauthorized port scans, identifying anomalous behavioral spikes (SYN floods, brute force attacks), and correlating Indicators of Compromise (IoC) with threat intelligence signatures.</p>
        `
    },
    {
        q: 'Why is NetSentinel an IDS rather than an inline IPS?',
        a: `
            <p>NetSentinel is architected as an <strong>Intrusion Detection System (IDS)</strong> rather than an inline Intrusion Prevention System (IPS).</p>
            <p>Automatic inline IP blocking requires OS kernel administrator rights and carries severe risk: an attacker spoofing the source IP of your default gateway or DNS resolver could cause an IPS to sever legitimate connectivity. NetSentinel alerts and logs forensic evidence without risking denial-of-service on critical network routes.</p>
        `
    },
    {
        q: 'What should you look for when choosing network security monitoring tools?',
        a: `
            <p>Key requirements include: <strong>Real-time packet inspection</strong>, lightweight socket concurrency (such as Java 21 Project Loom virtual threads), robust forensic logging (SQLite WAL mode), role-based access control (RBAC), and intuitive SOC visualization.</p>
        `
    },
    {
        q: 'What are the best practices for network security monitoring?',
        a: `
            <p>1. Deploy decoy honeypot listeners on sensitive non-standard ports.<br>
            2. Combine deterministic rule-based signatures with statistical machine learning anomaly detection.<br>
            3. Sanitize all incoming network telemetry to prevent Cross-Site Scripting (XSS) in SOC consoles.<br>
            4. Regularly replay historical PCAP traces for regression testing and analyst training.</p>
        `
    },
    {
        q: 'How does NetSentinel achieve high throughput without thread exhaustion?',
        a: `
            <p>NetSentinel leverages <strong>Java 21 Project Loom Virtual Threads</strong>. Unlike traditional thread pools that lock native OS threads on slow socket read operations, virtual threads are managed by the JVM runtime, allowing hundreds of concurrent decoy probe connections with negligible memory overhead.</p>
        `
    }
];

function initFaqSection() {
    const list = document.getElementById('faqQuestionsList');
    if (!list) return;

    list.innerHTML = FAQ_ITEMS.map((item, idx) => `
        <div class="faq-q-item ${idx === 0 ? 'active' : ''}" onclick="selectFaqItem(${idx})">
            <span>${item.q}</span>
            <span class="faq-arrow">→</span>
        </div>
    `).join('');

    selectFaqItem(0);
}

function selectFaqItem(index) {
    document.querySelectorAll('.faq-q-item').forEach((el, idx) => {
        el.classList.toggle('active', idx === index);
    });

    const item = FAQ_ITEMS[index];
    const titleEl = document.getElementById('faqActiveTitle');
    const contentEl = document.getElementById('faqActiveContent');

    if (titleEl) titleEl.textContent = item.q;
    if (contentEl) contentEl.innerHTML = item.a;
}

// ==========================================
// ATTACK SIMULATIONS & ACTIONS (ADMIN PROTECTED)
// ==========================================
async function triggerAttack(type) {
    playAlertAlarm('high');

    if (type === 'port-scan') setAttackState('port_scan');
    else if (type === 'syn-flood') setAttackState('syn_flood');
    else if (type === 'brute-force') setAttackState('brute_force');

    try {
        await fetch(`${API_BASE}/api/attack/${type}`, { method: 'POST' });
        // Immediate fetch to update alerts, forensics, metrics, and node inventory on first click
        await fetchData();
        setTimeout(fetchData, 200);
        setTimeout(fetchData, 600);
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

function promptClearAlerts() {
    const modal = document.getElementById('clearConfirmModal');
    if (modal) modal.style.display = 'flex';
}

function closeClearModal() {
    const modal = document.getElementById('clearConfirmModal');
    if (modal) modal.style.display = 'none';
}

function handleModalBackdropClick(event) {
    if (event.target && event.target.id === 'clearConfirmModal') {
        closeClearModal();
    }
}

window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeClearModal();
        closeSignatureModal();
        closeUserManagementModal();
    }
});

async function executeClearAlerts() {
    closeClearModal();

    setAttackState('normal');

    const alertsContainer = document.getElementById('alertsContainer');
    if (alertsContainer) {
        alertsContainer.innerHTML = `
            <div style="text-align: center; color: var(--text-muted); padding: 3rem 0; font-size: 0.85rem;">
                🛡️ No security alerts detected yet. Listening for traffic...
            </div>`;
    }

    const topIpsTableBody = document.getElementById('topIpsTableBody');
    if (topIpsTableBody) {
        topIpsTableBody.innerHTML = `
            <tr>
                <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">
                    No attacking hosts detected yet
                </td>
            </tr>`;
    }

    const elPort = document.getElementById('sumPortScan');
    const elBrute = document.getElementById('sumBruteForce');
    const elSyn = document.getElementById('sumSynFlood');
    const elActive = document.getElementById('activeAlertsCount');
    if (elPort) elPort.textContent = '0';
    if (elBrute) elBrute.textContent = '0';
    if (elSyn) elSyn.textContent = '0';
    if (elActive) elActive.textContent = '0';

    lastAlertsFingerprint = 'EMPTY';
    lastTopIpsFingerprint = 'EMPTY';
    lastSummaryJson = '';

    cachedAlerts = [];
    updateVulnDashboardWidgets([]);
    renderDetailedVulnTable([]);
    syncNodesWithAlerts([]);
    renderThreatMap();
    updateSensorHealthDonut();
    syncSignaturesWithAlerts([]);

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

    setTimeout(fetchData, 400);
}

// ==========================================
// APPLICATION LIFECYCLE INITIALIZATION
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initLanguage();
    initDropdowns();
    initEcgCanvas();
    fetchCurrentUser();

    const userMgmtWrapper = document.getElementById('userMgmtWrapper');
    if (userMgmtWrapper) {
        userMgmtWrapper.addEventListener('mouseenter', () => {
            updateHoverPendingList();
        });
    }

    // Initialize rich views
    initDetailedVulnFilters();
    updateVulnDashboardWidgets([]);
    renderDetailedVulnTable([]);
    syncNodesWithAlerts([]);
    syncSignaturesWithAlerts([]);
    initFaqSection();
    renderThreatMap();
    initWanCanvas();
    updateSensorHealthDonut();

    // Start background telemetry
    startPolling();
    fetchData();
});

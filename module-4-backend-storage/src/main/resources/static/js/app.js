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
let currentUser = { username: 'admin', isAdmin: true, roles: ['ROLE_ADMIN'] };

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
        console.warn('Auth status check (using local state fallback):', e);
    }

    currentUser = { username: 'admin', isAdmin: true, roles: ['ROLE_ADMIN'] };
    renderUserBadge(currentUser);
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
    const usernameEl = document.getElementById('usernameDisplay');
    const roleEl = document.getElementById('roleDisplay');
    const brandLabel = document.getElementById('brandConsoleLabel');

    if (usernameEl) {
        usernameEl.textContent = 'admin';
    }
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
        // Authentic ECG rhythm pulse (P-Q-R-S-T)
        const period = 52;
        const pos = tick % period;
        let offset = 0;
        if (pos === 10) offset = -6;        // P wave
        else if (pos === 11) offset = -10;
        else if (pos === 12) offset = -5;
        else if (pos === 15) offset = 7;     // Q dip
        else if (pos === 16) offset = -50;   // R sharp upward peak
        else if (pos === 17) offset = 26;    // S downward rebound
        else if (pos === 18) offset = 0;
        else if (pos === 23) offset = -12;   // T gentle dome
        else if (pos === 24) offset = -16;
        else if (pos === 25) offset = -11;
        else if (pos === 26) offset = -3;
        else {
            offset = Math.sin(tick * 0.12) * 1.5; // subtle ambient network hum
        }
        return baseline + offset;
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

        if (cachedAlerts && cachedAlerts.length > 0) {
            const newest = cachedAlerts[0];
            const alertTime = new Date(newest.timestamp).getTime();
            const now = Date.now();
            if (now - alertTime < 8000) {
                if (newest.attack_type === 'syn_flood') setAttackState('syn_flood');
                else if (newest.attack_type === 'port_scan') setAttackState('port_scan');
                else if (newest.attack_type === 'brute_force') setAttackState('brute_force');
            }
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

        const methodBadge = (a.detection_method || '').toLowerCase() === 'ml'
            ? `<span class="badge badge-method-ml" title="Unsupervised Isolation Forest Engine">🧠 ML</span>`
            : `<span class="badge badge-method-rule" title="Deterministic Stateful Rule Engine">⚙️ RULE</span>`;

        return `
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.35rem;">
                        <span class="status-dot status-dot-${safeSev}"></span>
                        <span class="badge badge-${safeSev}">[${safeSev.toUpperCase()}]</span>
                    </div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); font-size: 0.76rem;">#${safeId}</div>
                    <div style="font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono);">${timeFormatted}</div>
                </td>
                <td>
                    <div style="font-weight: 700; color: var(--text-primary); font-size: 0.8rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 135px;">${typeLabel}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted); text-transform: uppercase; font-family: var(--font-mono);">${typeCategory}</div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 600; color: #f87171; font-size: 0.78rem;">${safeSrc}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted);">Attacker</div>
                </td>
                <td>
                    <div style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-blue); font-size: 0.78rem;">${safeDst}</div>
                    <div style="font-size: 0.66rem; color: var(--text-muted);">Target</div>
                </td>
                <td>${methodBadge}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.3rem;">
                        <span style="font-family: var(--font-mono); font-weight: 700; font-size: 0.76rem; color: var(--accent-blue);">${confPct}%</span>
                        <div style="width: 24px; height: 4px; background: rgba(148, 163, 184, 0.2); border-radius: 2px; overflow: hidden;">
                            <div style="width: ${confPct}%; height: 100%; background: var(--accent-blue);"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <div style="font-size: 0.74rem; color: var(--text-secondary); line-height: 1.35; word-break: break-word;">
                        ${safeDetails}
                    </div>
                </td>
                <td>
                    <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); font-size: 0.68rem; white-space: nowrap;">🛡️ MITIGATED</span>
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
const MOCK_NODES = [
    { name: 'Aruba_3810M-stack', ip: '10.1.21.10', os: 'HPE', role: 'Aruba JL074A Switch', tracked: 'Last 7 days', risk: 85, total: 2, crit: 1, high: 1, med: 0, low: 0, none: 0 },
    { name: 'FortiSwitch-248E', ip: '10.1.21.12', os: 'Fortinet, Inc.', role: 'FSW_248E-F FPOE v7.2', tracked: 'Last 7 days', risk: 85, total: 2, crit: 1, high: 1, med: 0, low: 0, none: 0 },
    { name: 'EASTUBNT01v', ip: '10.1.21.14', os: 'Linux', role: 'Ubuntu Server 22.04 LTS', tracked: 'Older than 30 days', risk: 78, total: 36, crit: 6, high: 22, med: 8, low: 0, none: 0 },
    { name: 'DEN-PA100VM-A', ip: '10.1.21.15', os: 'Palo Alto Networks', role: 'PA-VM 7.1.0 Gateway', tracked: 'Older than 30 days', risk: 90, total: 69, crit: 10, high: 28, med: 30, low: 1, none: 0 },
    { name: 'EAST_vMX', ip: '10.1.21.16', os: 'Juniper Networks', role: 'vMX Core Router NetFlow', tracked: 'Older than 30 days', risk: 92, total: 69, crit: 10, high: 28, med: 30, low: 1, none: 0 },
    { name: 'LON-FortiFirewall-01', ip: '10.1.21.22', os: 'Fortinet, Inc.', role: 'FFW_VM64KVM Enterprise', tracked: 'Older than 30 days', risk: 65, total: 12, crit: 2, high: 4, med: 6, low: 0, none: 0 },
    { name: 'SIN-FortiFirewall-01', ip: '10.1.21.24', os: 'Fortinet, Inc.', role: 'FFW_VM64KVM Decoy Hub', tracked: 'Older than 30 days', risk: 65, total: 12, crit: 2, high: 4, med: 6, low: 0, none: 0 },
    { name: 'EAST-9300-1stFl', ip: '10.1.21.30', os: 'Cisco', role: 'Catalyst 9300 Switch', tracked: 'Older than 30 days', risk: 70, total: 18, crit: 2, high: 10, med: 6, low: 0, none: 0 },
    { name: 'EAST-FW-A', ip: '10.1.21.32', os: 'Cisco', role: 'Cisco ASA 5510SC Gateway', tracked: 'Older than 30 days', risk: 75, total: 54, crit: 4, high: 26, med: 23, low: 1, none: 0 },
    { name: 'DEN-7200-1A.demo.lab', ip: '10.1.21.40', os: 'Cisco', role: 'Cisco 7206 VXR Core', tracked: 'Older than 30 days', risk: 82, total: 199, crit: 2, high: 47, med: 19, low: 0, none: 0 },
    { name: 'DEN-3560-ASFlr1A', ip: '10.1.21.55', os: 'Cisco', role: 'Catalyst 3560X Distribution', tracked: 'Older than 30 days', risk: 80, total: 121, crit: 1, high: 59, med: 14, low: 0, none: 0 },
    { name: 'HONEYPOT-DECOY-01', ip: '192.168.1.90', os: 'Linux', role: 'Java 21 Project Loom Decoy', tracked: 'Last 24 hours', risk: 95, total: 42, crit: 18, high: 14, med: 10, low: 0, none: 0 }
];

function renderNodesTable(nodes = MOCK_NODES) {
    const tbody = document.getElementById('nodesTableBody');
    if (!tbody) return;

    tbody.innerHTML = nodes.map(n => `
        <tr>
            <td><span class="status-dot status-dot-critical"></span></td>
            <td>
                <span class="node-interactive-link" onmouseenter="showNodePopover(event, '${n.name}')" onmouseleave="hideNodePopover()">
                    ${n.name}
                </span>
            </td>
            <td>${n.os}</td>
            <td style="color: var(--text-secondary); font-size: 0.76rem;">${n.role}</td>
            <td style="color: var(--text-muted); font-size: 0.74rem;">${n.tracked}</td>
            <td>
                <div class="mini-risk-bar">
                    <div class="mini-risk-indicator" style="left: ${n.risk}%;"></div>
                </div>
            </td>
            <td><strong style="color: var(--text-primary); font-family: var(--font-mono);">${n.total}</strong></td>
            <td>
                <div style="display: flex; align-items: center; gap: 0.4rem; font-size: 0.74rem; font-family: var(--font-mono);">
                    <span style="color: #ef4444;">● ${n.crit}</span>
                    <span style="color: #ea580c;">● ${n.high}</span>
                    <span style="color: #eab308;">● ${n.med}</span>
                    <span style="color: #0284c7;">● ${n.low}</span>
                </div>
            </td>
        </tr>
    `).join('');
}

function showNodePopover(event, nodeName) {
    const pop = document.getElementById('nodeHoverPopover');
    if (!pop) return;

    const node = MOCK_NODES.find(n => n.name === nodeName) || {
        name: nodeName,
        ip: '10.1.21.16',
        os: 'vMX Gateway',
        role: 'NetFlow v9'
    };

    document.getElementById('popoverNodeName').textContent = node.name;
    document.getElementById('popoverIp').textContent = node.ip;
    document.getElementById('popoverType').textContent = node.os;

    // Position popover near mouse
    pop.style.left = `${event.clientX + 16}px`;
    pop.style.top = `${event.clientY - 30}px`;
    pop.classList.add('visible');
}

function hideNodePopover() {
    const pop = document.getElementById('nodeHoverPopover');
    if (pop) pop.classList.remove('visible');
}

function filterNodes() {
    const query = (document.getElementById('nodeSearchInput')?.value || '').toLowerCase();
    const filtered = MOCK_NODES.filter(n =>
        n.name.toLowerCase().includes(query) ||
        n.ip.toLowerCase().includes(query) ||
        n.os.toLowerCase().includes(query)
    );
    renderNodesTable(filtered);
}

// ==========================================
// VIEW 4: THREAT SIGNATURE REGISTRY & MODAL
// ==========================================
function renderSignaturesTable() {
    const tbody = document.getElementById('signaturesTableBody');
    if (!tbody) return;

    tbody.innerHTML = MOCK_VULNS.map(v => `
        <tr>
            <td><span class="badge badge-${v.sev}">[${v.sev.toUpperCase()}]</span></td>
            <td><strong style="color: var(--accent-blue); font-family: var(--font-mono);">${v.cve}</strong></td>
            <td><span class="badge badge-low">${v.proto}</span></td>
            <td>${v.desc}</td>
            <td><strong style="color: ${v.score >= 10 ? '#ef4444' : '#f59e0b'}; font-family: var(--font-mono);">${v.score}</strong></td>
            <td><span style="color: var(--accent-green); font-size: 0.76rem;">● Active</span></td>
            <td>
                <button class="btn" onclick="openSignatureModal('${v.cve}')" style="padding: 0.2rem 0.6rem; font-size: 0.72rem;">Inspect</button>
            </td>
        </tr>
    `).join('');
}

function openSignatureModal(cveId) {
    const v = MOCK_VULNS.find(x => x.cve === cveId) || MOCK_VULNS[0];
    document.getElementById('modalSigTitle').textContent = `${v.cve} Vulnerability Summary`;
    document.getElementById('modalSigScore').textContent = v.score.toFixed(1);
    document.getElementById('modalSigSev').textContent = `[${v.sev.toUpperCase()}]`;
    document.getElementById('modalSigSummary').textContent = v.desc;
    document.getElementById('modalSigLink').href = `https://nvd.nist.gov/vuln/detail/${v.cve}`;
    document.getElementById('signatureDetailModal').style.display = 'flex';
}

function closeSignatureModal() {
    const modal = document.getElementById('signatureDetailModal');
    if (modal) modal.style.display = 'none';
}

function filterSignatures() {
    const query = (document.getElementById('sigSearchInput')?.value || '').toLowerCase();
    const filtered = MOCK_VULNS.filter(v =>
        v.cve.toLowerCase().includes(query) ||
        v.desc.toLowerCase().includes(query) ||
        v.proto.toLowerCase().includes(query)
    );
    const tbody = document.getElementById('signaturesTableBody');
    if (!tbody) return;

    tbody.innerHTML = filtered.map(v => `
        <tr>
            <td><span class="badge badge-${v.sev}">[${v.sev.toUpperCase()}]</span></td>
            <td><strong style="color: var(--accent-blue); font-family: var(--font-mono);">${v.cve}</strong></td>
            <td><span class="badge badge-low">${v.proto}</span></td>
            <td>${v.desc}</td>
            <td><strong style="color: ${v.score >= 10 ? '#ef4444' : '#f59e0b'}; font-family: var(--font-mono);">${v.score}</strong></td>
            <td><span style="color: var(--accent-green); font-size: 0.76rem;">● Active</span></td>
            <td>
                <button class="btn" onclick="openSignatureModal('${v.cve}')" style="padding: 0.2rem 0.6rem; font-size: 0.72rem;">Inspect</button>
            </td>
        </tr>
    `).join('');
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

    // Initialize rich views
    initDetailedVulnFilters();
    updateVulnDashboardWidgets([]);
    renderDetailedVulnTable([]);
    renderNodesTable();
    renderSignaturesTable();
    initFaqSection();

    // Start background telemetry
    startPolling();
    fetchData();
});

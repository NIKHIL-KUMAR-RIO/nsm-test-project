package com.nsm.backend.controller;

import com.nsm.backend.service.NsmPipelineCoordinator;
import com.nsm.backend.service.TrafficStatsService;
import com.nsm.backend.storage.AlertRepository;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Spring Boot REST Controller (Person 4):
 * Exposes API endpoints for Person 5's Dashboard, pipeline ingestion,
 * and authenticated attack simulations. Hardened with Tier 1 input validation & CORS controls.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
}, allowCredentials = "true")
public class NsmApiController {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$"
    );

    private final AlertRepository alertRepository;
    private final TrafficStatsService trafficStatsService;
    private final NsmPipelineCoordinator coordinator;

    public NsmApiController(
            AlertRepository alertRepository,
            TrafficStatsService trafficStatsService,
            NsmPipelineCoordinator coordinator
    ) {
        this.alertRepository = alertRepository;
        this.trafficStatsService = trafficStatsService;
        this.coordinator = coordinator;
    }

    private boolean isValidIpv4(String ip) {
        return ip != null && IPV4_PATTERN.matcher(ip.trim()).matches();
    }

    // ==========================================
    // 0. AUTHENTICATION & SESSION CONTEXT
    // ==========================================

    @GetMapping("/auth/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("authenticated", false));
        }
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        boolean isAdmin = roles.contains("ROLE_ADMIN");
        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                .header("Pragma", "no-cache")
                .body(Map.of(
                        "authenticated", true,
                        "username", authentication.getName(),
                        "roles", roles,
                        "isAdmin", isAdmin
                ));
    }

    // ==========================================
    // 1. PUBLIC CONTRACT (For Module 5 Dashboard)
    // ==========================================

    @GetMapping("/alerts")
    public ResponseEntity<List<AlertData>> getAlerts(@RequestParam(defaultValue = "50") int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        return ResponseEntity.ok(alertRepository.findRecent(safeLimit));
    }

    @GetMapping("/traffic-stats")
    public ResponseEntity<Map<String, Object>> getTrafficStats() {
        return ResponseEntity.ok(trafficStatsService.getTrafficStats());
    }

    @GetMapping("/summary")
    public ResponseEntity<Map<String, Integer>> getSummary() {
        return ResponseEntity.ok(alertRepository.countByAttackType());
    }

    @GetMapping("/top-ips")
    public ResponseEntity<List<Map<String, Object>>> getTopIps(@RequestParam(defaultValue = "5") int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 50));
        return ResponseEntity.ok(alertRepository.findTopSourceIps(safeLimit));
    }

    // ==========================================
    // 2. INGESTION ENDPOINTS (From Modules 1-3)
    // ==========================================

    @PostMapping("/ingest/packet")
    public ResponseEntity<Map<String, String>> ingestPacket(@RequestBody PacketData packet) {
        if (packet == null || !isValidIpv4(packet.srcIp()) || !isValidIpv4(packet.dstIp())) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid IP format in packet"));
        }
        coordinator.processIncomingPacket(packet);
        return ResponseEntity.ok(Map.of("status", "accepted"));
    }

    @PostMapping("/ingest/alert")
    public ResponseEntity<Map<String, String>> ingestAlert(@RequestBody AlertData alert) {
        if (alert == null || !isValidIpv4(alert.srcIp()) || !isValidIpv4(alert.dstIp())) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid IP format in alert"));
        }
        alertRepository.save(alert);
        return ResponseEntity.ok(Map.of("status", "saved", "alert_id", alert.alertId()));
    }

    @RequestMapping(value = {"/alerts", "/alerts/clear"}, method = {RequestMethod.POST, RequestMethod.DELETE})
    public ResponseEntity<Map<String, String>> clearAlerts() {
        alertRepository.clearAll();
        coordinator.resetEngines();
        return ResponseEntity.ok(Map.of("status", "cleared"));
    }

    // ==========================================
    // 3. ATTACK SIMULATION DEMO TRIGGERS (ADMIN ONLY)
    // ==========================================

    @PostMapping("/attack/port-scan")
    public ResponseEntity<Map<String, String>> triggerPortScan(
            @RequestParam(defaultValue = "192.168.1.50") String attackerIp,
            @RequestParam(defaultValue = "10.0.0.1") String victimIp,
            @RequestParam(defaultValue = "20") int startPort,
            @RequestParam(defaultValue = "45") int endPort
    ) {
        if (!isValidIpv4(attackerIp) || !isValidIpv4(victimIp)) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid IPv4 address specified"));
        }
        if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 || startPort > endPort) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid port range (must be 1-65535 and start <= end)"));
        }
        coordinator.triggerPortScan(attackerIp, victimIp, startPort, endPort);
        return ResponseEntity.ok(Map.of("status", "success", "message", "Port scan triggered"));
    }

    @PostMapping("/attack/syn-flood")
    public ResponseEntity<Map<String, String>> triggerSynFlood(
            @RequestParam(defaultValue = "192.168.1.99") String attackerIp,
            @RequestParam(defaultValue = "10.0.0.1") String victimIp,
            @RequestParam(defaultValue = "80") int targetPort,
            @RequestParam(defaultValue = "60") int count
    ) {
        if (!isValidIpv4(attackerIp) || !isValidIpv4(victimIp)) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid IPv4 address specified"));
        }
        if (targetPort < 1 || targetPort > 65535) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Target port must be within 1-65535"));
        }
        if (count < 1 || count > 5000) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Count must be between 1 and 5000"));
        }
        coordinator.triggerSynFlood(attackerIp, victimIp, targetPort, count);
        return ResponseEntity.ok(Map.of("status", "success", "message", "SYN flood triggered"));
    }

    @PostMapping("/attack/brute-force")
    public ResponseEntity<Map<String, String>> triggerBruteForce(
            @RequestParam(defaultValue = "192.168.1.77") String attackerIp,
            @RequestParam(defaultValue = "10.0.0.1") String victimIp,
            @RequestParam(defaultValue = "22") int servicePort,
            @RequestParam(defaultValue = "12") int attempts
    ) {
        if (!isValidIpv4(attackerIp) || !isValidIpv4(victimIp)) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid IPv4 address specified"));
        }
        if (servicePort < 1 || servicePort > 65535) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Service port must be within 1-65535"));
        }
        if (attempts < 1 || attempts > 500) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Attempts must be between 1 and 500"));
        }
        coordinator.triggerBruteForce(attackerIp, victimIp, servicePort, attempts);
        return ResponseEntity.ok(Map.of("status", "success", "message", "Brute force triggered"));
    }

    @PostMapping({"/attack/pcap-upload", "/upload-pcap"})
    public ResponseEntity<Map<String, Object>> uploadPcap(@RequestParam("file") MultipartFile file) {
        try {
            int packets = coordinator.replayPcapStream(file.getInputStream());
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "filename", file.getOriginalFilename(),
                    "packets_queued", packets
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", e.getMessage()));
        }
    }
}

package com.nsm.backend.controller;

import com.nsm.backend.service.NsmPipelineCoordinator;
import com.nsm.backend.service.TrafficStatsService;
import com.nsm.backend.storage.AlertRepository;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import com.nsm.backend.storage.UserEntity;
import com.nsm.backend.storage.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Spring Boot REST Controller (Person 4):
 * Exposes API endpoints for Person 5's Dashboard, pipeline ingestion,
 * authenticated attack simulations, and Option A User Management / Registration.
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

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private final AlertRepository alertRepository;
    private final TrafficStatsService trafficStatsService;
    private final NsmPipelineCoordinator coordinator;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public NsmApiController(
            AlertRepository alertRepository,
            TrafficStatsService trafficStatsService,
            NsmPipelineCoordinator coordinator,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.alertRepository = alertRepository;
        this.trafficStatsService = trafficStatsService;
        this.coordinator = coordinator;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Value("${nsm.security.admin-code:NSM-ADMIN-2026}")
    private String adminInviteCode;

    private boolean isValidIpv4(String ip) {
        return ip != null && IPV4_PATTERN.matcher(ip.trim()).matches();
    }

    public record RegisterRequest(String fullName, String email, String username, String password, String adminCode) {}

    // ==========================================
    // 0. AUTHENTICATION & USER MANAGEMENT (OPTION A)
    // ==========================================

    @PostMapping("/auth/register")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody(required = false) RegisterRequest req) {
        if (req == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Registration request body is required"));
        }
        String fullName = req.fullName() != null ? req.fullName().trim() : "";
        String email = req.email() != null ? req.email().trim().toLowerCase() : "";
        String username = req.username() != null ? req.username().trim().toLowerCase() : "";
        String password = req.password() != null ? req.password() : "";

        if (fullName.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Full name is required"));
        }
        if (email.isBlank() || !EMAIL_PATTERN.matcher(email).matches()) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "A valid email address is required"));
        }
        if (username.length() < 3 || username.length() > 30 || !username.matches("^[a-zA-Z0-9_.-]+$")) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Username must be 3-30 characters (alphanumeric, dots, hyphens, underscores)"));
        }
        if (password.length() < 6) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Password must be at least 6 characters in length"));
        }
        if (userRepository.findByEmail(email).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("status", "error", "message", "Email address is already registered"));
        }
        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.status(409).body(Map.of("status", "error", "message", "Username is already registered"));
        }

        boolean grantAdmin = false;
        String requestedCode = req.adminCode() != null ? req.adminCode().trim() : "";
        if (!requestedCode.isEmpty()) {
            if (adminInviteCode != null && !adminInviteCode.isBlank() && requestedCode.equals(adminInviteCode.trim())) {
                grantAdmin = true;
            } else {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "Invalid Team Authorization Code. Leave blank to request standard Analyst access."
                ));
            }
        }

        String role = grantAdmin ? "ADMIN" : "ANALYST";
        String accountStatus = grantAdmin ? "ACTIVE" : "PENDING";

        String hash = passwordEncoder.encode(password);
        UserEntity newUser = new UserEntity(
                null,
                email,
                username,
                fullName,
                hash,
                role,
                accountStatus,
                java.time.Instant.now().toString(),
                null
        );
        UserEntity saved = userRepository.save(newUser);

        if (grantAdmin) {
            return ResponseEntity.status(201).body(Map.of(
                    "status", "admin_activated",
                    "role", "ADMIN",
                    "message", "Administrator authorization verified! Account created and activated immediately. You can now sign in.",
                    "username", saved.username(),
                    "email", saved.email()
            ));
        }

        return ResponseEntity.status(201).body(Map.of(
                "status", "pending_approval",
                "role", "ANALYST",
                "message", "Registration submitted successfully! Your account is pending administrator approval before you can log in.",
                "username", saved.username(),
                "email", saved.email()
        ));
    }

    @GetMapping("/auth/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body(Map.of("authenticated", false));
        }
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        boolean isAdmin = roles.contains("ROLE_ADMIN");
        boolean isAnalyst = roles.contains("ROLE_ANALYST");

        var userOpt = userRepository.findByUsernameOrEmail(authentication.getName());
        String email = userOpt.map(UserEntity::email).orElse("");
        String fullName = userOpt.map(UserEntity::fullName).orElse(authentication.getName());
        long pendingCount = isAdmin ? userRepository.countPending() : 0L;

        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                .header("Pragma", "no-cache")
                .body(Map.of(
                        "authenticated", true,
                        "username", authentication.getName(),
                        "email", email,
                        "fullName", fullName,
                        "roles", roles,
                        "isAdmin", isAdmin,
                        "isAnalyst", isAnalyst,
                        "pendingCount", pendingCount
                ));
    }

    @GetMapping("/admin/users")
    public ResponseEntity<Map<String, Object>> listAllUsers() {
        List<Map<String, Object>> userList = userRepository.findAll().stream()
                .map(u -> Map.<String, Object>of(
                        "id", u.id(),
                        "email", u.email(),
                        "username", u.username(),
                        "fullName", u.fullName(),
                        "role", u.role(),
                        "accountStatus", u.accountStatus(),
                        "createdAt", u.createdAt(),
                        "lastLogin", u.lastLogin() != null ? u.lastLogin() : "Never"
                ))
                .toList();
        return ResponseEntity.ok(Map.of(
                "users", userList,
                "total", userList.size(),
                "pending", userRepository.countPending()
        ));
    }

    @PostMapping("/admin/users/{id}/approve")
    public ResponseEntity<Map<String, Object>> approveUser(@PathVariable Long id) {
        var userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        userRepository.updateStatus(id, "ACTIVE");
        return ResponseEntity.ok(Map.of("status", "success", "message", "User account approved and activated", "userId", id));
    }

    @PostMapping("/admin/users/{id}/disable")
    public ResponseEntity<Map<String, Object>> disableUser(@PathVariable Long id, Authentication auth) {
        var userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        UserEntity user = userOpt.get();
        if (auth != null && (user.username().equalsIgnoreCase(auth.getName()) || user.email().equalsIgnoreCase(auth.getName()))) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Administrators cannot disable their own account"));
        }
        userRepository.updateStatus(id, "DISABLED");
        return ResponseEntity.ok(Map.of("status", "success", "message", "User account has been disabled", "userId", id));
    }

    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable Long id, Authentication auth) {
        var userOpt = userRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        UserEntity user = userOpt.get();
        if (auth != null && (user.username().equalsIgnoreCase(auth.getName()) || user.email().equalsIgnoreCase(auth.getName()))) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Administrators cannot delete their own account"));
        }
        userRepository.delete(id);
        return ResponseEntity.ok(Map.of("status", "success", "message", "User account has been deleted", "userId", id));
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

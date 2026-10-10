package com.nsm.backend.controller;

import com.nsm.backend.service.NsmPipelineCoordinator;
import com.nsm.backend.service.TrafficStatsService;
import com.nsm.backend.storage.AlertRepository;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * Spring Boot REST Controller (Person 4):
 * Exposes the frozen API contract for Person 5's Dashboard and ingestion endpoints.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class NsmApiController {

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

    // ==========================================
    // 1. FROZEN PUBLIC CONTRACT (For Module 5)
    // ==========================================

    @GetMapping("/alerts")
    public ResponseEntity<List<AlertData>> getAlerts(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(alertRepository.findRecent(limit));
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
        return ResponseEntity.ok(alertRepository.findTopSourceIps(limit));
    }

    // ==========================================
    // 2. INGESTION ENDPOINTS (From Modules 1-3)
    // ==========================================

    @PostMapping("/ingest/packet")
    public ResponseEntity<Map<String, String>> ingestPacket(@RequestBody PacketData packet) {
        coordinator.processIncomingPacket(packet);
        return ResponseEntity.ok(Map.of("status", "accepted"));
    }

    @PostMapping("/ingest/alert")
    public ResponseEntity<Map<String, String>> ingestAlert(@RequestBody AlertData alert) {
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
    // 3. ATTACK SIMULATION DEMO TRIGGERS
    // ==========================================

    @PostMapping("/attack/port-scan")
    public ResponseEntity<Map<String, String>> triggerPortScan(
            @RequestParam(defaultValue = "192.168.1.50") String attackerIp,
            @RequestParam(defaultValue = "10.0.0.1") String victimIp,
            @RequestParam(defaultValue = "20") int startPort,
            @RequestParam(defaultValue = "45") int endPort
    ) {
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

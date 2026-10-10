package com.nsm.rule.engine;

import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * High-performance Rule-Based Detection Engine (Person 2).
 * Implements sliding time-windows with ArrayDeque and cooldown deduplication.
 */
public class RuleEngine {

    // Thresholds
    private final int portScanThreshold;
    private final int portScanWindowSec;
    private final int synFloodThreshold;
    private final int synFloodWindowSec;
    private final int bruteForceThreshold;
    private final int bruteForceWindowSec;
    private final int cooldownSeconds;

    // Known services for brute force tracking (including decoy ports)
    private static final Set<Integer> BRUTE_FORCE_PORTS = Set.of(21, 22, 23, 2222, 3389, 8080, 8088, 8888, 9090);

    // Designated Decoy Honeypot Ports
    private static final Set<Integer> DECOY_PORTS = Set.of(2222, 8088, 8888, 9090);

    // State Tracking
    // Port Scan: (srcIp -> (dstPort -> timestamp))
    private final Map<String, Map<Integer, Instant>> portScanMap = new ConcurrentHashMap<>();

    // SYN Flood: (dstIp:dstPort -> ArrayDeque<Instant>)
    private final Map<String, ArrayDeque<Instant>> synFloodMap = new ConcurrentHashMap<>();

    // Brute Force: (srcIp:dstIp:dstPort -> ArrayDeque<Instant>)
    private final Map<String, ArrayDeque<Instant>> bruteForceMap = new ConcurrentHashMap<>();

    // Alert Cooldown: (srcIp:attackType -> lastAlertTime)
    private final Map<String, Instant> cooldownMap = new ConcurrentHashMap<>();

    public RuleEngine() {
        this(15, 5, 50, 2, 10, 30, 5);
    }

    public RuleEngine(
            int portScanThreshold,
            int portScanWindowSec,
            int synFloodThreshold,
            int synFloodWindowSec,
            int bruteForceThreshold,
            int bruteForceWindowSec,
            int cooldownSeconds
    ) {
        this.portScanThreshold = portScanThreshold;
        this.portScanWindowSec = portScanWindowSec;
        this.synFloodThreshold = synFloodThreshold;
        this.synFloodWindowSec = synFloodWindowSec;
        this.bruteForceThreshold = bruteForceThreshold;
        this.bruteForceWindowSec = bruteForceWindowSec;
        this.cooldownSeconds = cooldownSeconds;
    }

    public List<AlertData> evaluate(PacketData packet) {
        List<AlertData> alerts = new ArrayList<>();
        if (packet == null) return alerts;

        Instant now = packet.timestamp() != null ? packet.timestamp() : Instant.now();

        // 1. Port Scan Rule
        AlertData portScanAlert = evaluatePortScan(packet, now);
        if (portScanAlert != null) alerts.add(portScanAlert);

        // 2. SYN Flood Rule
        AlertData synFloodAlert = evaluateSynFlood(packet, now);
        if (synFloodAlert != null) alerts.add(synFloodAlert);

        // 3. Brute Force Rule
        AlertData bruteForceAlert = evaluateBruteForce(packet, now);
        if (bruteForceAlert != null) alerts.add(bruteForceAlert);

        // 4. Decoy Honeypot Trap Rule
        AlertData decoyAlert = evaluateDecoyProbe(packet, now);
        if (decoyAlert != null) alerts.add(decoyAlert);

        return alerts;
    }

    private AlertData evaluatePortScan(PacketData packet, Instant now) {
        if (!"TCP".equalsIgnoreCase(packet.protocol()) && !"UDP".equalsIgnoreCase(packet.protocol())) {
            return null;
        }

        String key = packet.srcIp() + "->" + packet.dstIp();
        Map<Integer, Instant> ports = portScanMap.computeIfAbsent(key, k -> new ConcurrentHashMap<>());
        ports.put(packet.dstPort(), now);

        // Evict older than window
        Instant cutoff = now.minusSeconds(portScanWindowSec);
        ports.entrySet().removeIf(e -> e.getValue().isBefore(cutoff));

        int uniquePorts = ports.size();
        if (uniquePorts >= portScanThreshold) {
            String cooldownKey = packet.srcIp() + ":port_scan";
            if (isCooldownExpired(cooldownKey, now)) {
                cooldownMap.put(cooldownKey, now);
                return AlertData.create(
                        "port_scan",
                        "high",
                        packet.srcIp(),
                        packet.dstIp(),
                        String.format("Scanned %d unique ports within %d seconds", uniquePorts, portScanWindowSec),
                        0.95,
                        "rule"
                );
            }
        }
        return null;
    }

    private AlertData evaluateSynFlood(PacketData packet, Instant now) {
        if (!"TCP".equalsIgnoreCase(packet.protocol())) return null;
        String flags = packet.flags() != null ? packet.flags() : "";
        if (!flags.contains("SYN") || flags.contains("ACK")) return null;

        String key = packet.dstIp() + ":" + packet.dstPort();
        ArrayDeque<Instant> queue = synFloodMap.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (queue) {
            queue.addLast(now);
            Instant cutoff = now.minusSeconds(synFloodWindowSec);
            while (!queue.isEmpty() && queue.peekFirst().isBefore(cutoff)) {
                queue.pollFirst();
            }

            int count = queue.size();
            if (count >= synFloodThreshold) {
                String cooldownKey = packet.srcIp() + ":syn_flood";
                if (isCooldownExpired(cooldownKey, now)) {
                    cooldownMap.put(cooldownKey, now);
                    return AlertData.create(
                            "syn_flood",
                            "high",
                            packet.srcIp(),
                            packet.dstIp(),
                            String.format("High SYN rate: %d SYN packets to port %d within %d seconds",
                                    count, packet.dstPort(), synFloodWindowSec),
                            0.90,
                            "rule"
                    );
                }
            }
        }
        return null;
    }

    private AlertData evaluateBruteForce(PacketData packet, Instant now) {
        if (!"TCP".equalsIgnoreCase(packet.protocol())) return null;
        if (!BRUTE_FORCE_PORTS.contains(packet.dstPort())) return null;

        String flags = packet.flags() != null ? packet.flags() : "";
        if (!flags.contains("SYN")) return null;

        String key = packet.srcIp() + "->" + packet.dstIp() + ":" + packet.dstPort();
        ArrayDeque<Instant> queue = bruteForceMap.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (queue) {
            queue.addLast(now);
            Instant cutoff = now.minusSeconds(bruteForceWindowSec);
            while (!queue.isEmpty() && queue.peekFirst().isBefore(cutoff)) {
                queue.pollFirst();
            }

            int attempts = queue.size();
            if (attempts >= bruteForceThreshold) {
                String cooldownKey = packet.srcIp() + ":brute_force";
                if (isCooldownExpired(cooldownKey, now)) {
                    cooldownMap.put(cooldownKey, now);
                    return AlertData.create(
                            "brute_force",
                            "medium",
                            packet.srcIp(),
                            packet.dstIp(),
                            String.format("Repeated authentication attempts: %d connections to service port %d in %ds",
                                    attempts, packet.dstPort(), bruteForceWindowSec),
                            0.85,
                            "rule"
                    );
                }
            }
        }
        return null;
    }

    private AlertData evaluateDecoyProbe(PacketData packet, Instant now) {
        if (packet == null || !DECOY_PORTS.contains(packet.dstPort())) return null;

        String cooldownKey = packet.srcIp() + ":decoy:" + packet.dstPort();
        if (isCooldownExpired(cooldownKey, now)) {
            cooldownMap.put(cooldownKey, now);
            return AlertData.create(
                    "port_scan",
                    "high",
                    packet.srcIp(),
                    packet.dstIp(),
                    String.format("Decoy Honeypot Trap Triggered: unauthorized connection probe on port %d", packet.dstPort()),
                    0.95,
                    "rule"
            );
        }
        return null;
    }

    private boolean isCooldownExpired(String key, Instant now) {
        Instant last = cooldownMap.get(key);
        return last == null || Duration.between(last, now).getSeconds() >= cooldownSeconds;
    }

    public void reset() {
        portScanMap.clear();
        synFloodMap.clear();
        bruteForceMap.clear();
        cooldownMap.clear();
    }
}

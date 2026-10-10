package com.nsm.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.engine.RuleEngine;
import com.nsm.rule.model.AlertData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    private ObjectMapper mapper;
    private RuleEngine ruleEngine;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        // Custom thresholds for fast testing: 4 ports for scan, 5 SYNs for flood, 3 for brute force
        ruleEngine = new RuleEngine(4, 5, 5, 2, 3, 10, 5);
    }

    @Test
    void testAlertMatchesFrozenJsonSchema() throws Exception {
        AlertData alert = AlertData.create(
                "port_scan",
                "high",
                "192.168.1.5",
                "10.0.0.1",
                "Scanned 25 ports in 3 seconds",
                0.9,
                "rule"
        );

        String json = mapper.writeValueAsString(alert);
        JsonNode node = mapper.readTree(json);

        assertTrue(node.has("alert_id"));
        assertTrue(node.has("timestamp"));
        assertTrue(node.has("attack_type"));
        assertTrue(node.has("severity"));
        assertTrue(node.has("src_ip"));
        assertTrue(node.has("dst_ip"));
        assertTrue(node.has("details"));
        assertTrue(node.has("confidence"));
        assertTrue(node.has("detection_method"));

        assertEquals("port_scan", node.get("attack_type").asText());
        assertEquals("high", node.get("severity").asText());
        assertEquals("192.168.1.5", node.get("src_ip").asText());
        assertEquals(0.9, node.get("confidence").asDouble(), 0.001);
        assertEquals("rule", node.get("detection_method").asText());
    }

    @Test
    void testPortScanDetection() {
        Instant now = Instant.now();
        List<AlertData> triggered = new ArrayList<>();

        for (int p = 20; p <= 24; p++) {
            PacketData pkt = PacketData.create(now, "192.168.1.50", "10.0.0.1", 40000 + p, p, "TCP", "SYN", 60);
            triggered.addAll(ruleEngine.evaluate(pkt));
        }

        assertFalse(triggered.isEmpty(), "Rule engine must trigger port scan alert upon reaching port threshold");
        AlertData a = triggered.get(0);
        assertEquals("port_scan", a.attackType());
        assertEquals("high", a.severity());
        assertEquals("192.168.1.50", a.srcIp());
    }

    @Test
    void testSynFloodDetection() {
        Instant now = Instant.now();
        List<AlertData> triggered = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            PacketData pkt = PacketData.create(now, "192.168.1.99", "10.0.0.1", 30000 + i, 80, "TCP", "SYN", 60);
            triggered.addAll(ruleEngine.evaluate(pkt));
        }

        assertFalse(triggered.isEmpty(), "Rule engine must trigger SYN flood alert");
        AlertData a = triggered.get(0);
        assertEquals("syn_flood", a.attackType());
        assertEquals("high", a.severity());
    }

    @Test
    void testBruteForceDetection() {
        Instant now = Instant.now();
        List<AlertData> triggered = new ArrayList<>();

        // Repeated attempts to port 22 (SSH)
        for (int i = 0; i < 4; i++) {
            PacketData pkt = PacketData.create(now, "192.168.1.77", "10.0.0.1", 50000 + i, 22, "TCP", "SYN", 60);
            triggered.addAll(ruleEngine.evaluate(pkt));
        }

        assertFalse(triggered.isEmpty(), "Rule engine must trigger brute force alert on port 22");
        AlertData a = triggered.get(0);
        assertEquals("brute_force", a.attackType());
        assertEquals("medium", a.severity());
    }
}

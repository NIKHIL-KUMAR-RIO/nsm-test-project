package com.nsm.anomaly;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nsm.anomaly.engine.AnomalyDetectionEngine;
import com.nsm.anomaly.extractor.FlowFeatureExtractor;
import com.nsm.anomaly.model.FlowFeatures;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AnomalyDetectionTest {

    private ObjectMapper mapper;
    private AnomalyDetectionEngine anomalyEngine;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        anomalyEngine = new AnomalyDetectionEngine(new FlowFeatureExtractor(5), 5);
    }

    @Test
    void testFlowFeatureExtractionCalculatesEntropy() {
        FlowFeatureExtractor extractor = new FlowFeatureExtractor(5);
        Instant now = Instant.now();

        FlowFeatures f = null;
        for (int p = 20; p <= 35; p++) {
            PacketData pkt = PacketData.create(now, "192.168.1.5", "10.0.0.1", 40000 + p, p, "TCP", "SYN", 60);
            f = extractor.updateAndExtract(pkt);
        }

        assertNotNull(f);
        assertEquals(16, f.packetCount());
        assertEquals(16, f.distinctDstPorts());
        assertTrue(f.portEntropy() > 3.0, "Entropy across 16 ports should be > 3.0");
    }

    @Test
    void testAnomalyDetectionProducesMlAlert() throws Exception {
        Instant now = Instant.now();
        Optional<AlertData> alertOpt = Optional.empty();

        for (int p = 20; p <= 35; p++) {
            PacketData pkt = PacketData.create(now, "192.168.1.5", "10.0.0.1", 40000 + p, p, "TCP", "SYN", 60);
            alertOpt = anomalyEngine.evaluate(pkt);
            if (alertOpt.isPresent()) break;
        }

        assertTrue(alertOpt.isPresent(), "Anomaly engine must trigger ML alert on high entropy port scan");
        AlertData alert = alertOpt.get();
        assertEquals("ml", alert.detectionMethod());
        assertEquals("port_scan", alert.attackType());

        String json = mapper.writeValueAsString(alert);
        JsonNode node = mapper.readTree(json);
        assertEquals("ml", node.get("detection_method").asText());
    }
}

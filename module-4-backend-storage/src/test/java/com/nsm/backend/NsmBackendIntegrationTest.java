package com.nsm.backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class NsmBackendIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testGetSummaryEndpoint() throws Exception {
        mockMvc.perform(get("/api/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.port_scan").exists())
                .andExpect(jsonPath("$.brute_force").exists())
                .andExpect(jsonPath("$.syn_flood").exists());
    }

    @Test
    void testGetTrafficStatsEndpoint() throws Exception {
        mockMvc.perform(get("/api/traffic-stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.packets_per_sec").isArray())
                .andExpect(jsonPath("$.timestamps").isArray());
    }

    @Test
    void testIngestAlertAndRetrieve() throws Exception {
        AlertData alert = AlertData.create(
                "port_scan",
                "high",
                "192.168.1.105",
                "10.0.0.1",
                "Scanned 20 ports in 2 seconds",
                0.95,
                "rule"
        );

        mockMvc.perform(post("/api/ingest/alert")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(alert)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("saved"));

        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].attack_type").value("port_scan"))
                .andExpect(jsonPath("$[0].src_ip").value("192.168.1.105"));
    }

    @Test
    void testIngestPacketPipelineExecution() throws Exception {
        PacketData packet = PacketData.create(
                Instant.now(),
                "192.168.1.55",
                "10.0.0.1",
                45000,
                80,
                "TCP",
                "SYN",
                60
        );

        mockMvc.perform(post("/api/ingest/packet")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(packet)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("accepted"));
    }
}

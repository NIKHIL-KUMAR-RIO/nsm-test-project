package com.nsm.backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
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
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testGetSummaryEndpoint() throws Exception {
        mockMvc.perform(get("/api/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.port_scan").exists())
                .andExpect(jsonPath("$.brute_force").exists())
                .andExpect(jsonPath("$.syn_flood").exists());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testGetTrafficStatsEndpoint() throws Exception {
        mockMvc.perform(get("/api/traffic-stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.packets_per_sec").isArray())
                .andExpect(jsonPath("$.timestamps").isArray());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
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
    @WithMockUser(username = "admin", roles = {"ADMIN"})
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

    // ==========================================
    // SECURITY HARDENING VERIFICATION TESTS
    // ==========================================

    @Test
    void testUnauthenticatedUserCannotAccessProtectedApi() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "guest", roles = {"USER"})
    void testNonAdminIsForbiddenFromDestructiveClearAction() throws Exception {
        mockMvc.perform(post("/api/alerts/clear"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testAdminIsAllowedToClearAlerts() throws Exception {
        mockMvc.perform(post("/api/alerts/clear"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("cleared"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testInputValidationRejectsInvalidIpAddress() throws Exception {
        mockMvc.perform(post("/api/attack/port-scan")
                        .param("attackerIp", "999.999.999.999")
                        .param("victimIp", "10.0.0.1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testInputValidationRejectsOutOfRangePort() throws Exception {
        mockMvc.perform(post("/api/attack/port-scan")
                        .param("attackerIp", "192.168.1.50")
                        .param("victimIp", "10.0.0.1")
                        .param("startPort", "70000")
                        .param("endPort", "80000"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testLogoutSucceedsAndRedirectsToLoginPage() throws Exception {
        mockMvc.perform(get("/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/login.html?logout=true"));

        mockMvc.perform(post("/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/login.html?logout=true"));
    }

    // ==========================================
    // OPTION A AUTHENTICATION & USER MANAGEMENT TESTS
    // ==========================================

    @Test
    void testUserRegistrationSucceedsWithPendingApproval() throws Exception {
        String uniqueSuffix = String.valueOf(System.currentTimeMillis() % 100000);
        String regPayload = """
            {
                "fullName": "Test Security Analyst",
                "email": "analyst%s@university.edu",
                "username": "analyst%s",
                "password": "SecurePassword123!"
            }
        """.formatted(uniqueSuffix, uniqueSuffix);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(regPayload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("pending_approval"))
                .andExpect(jsonPath("$.username").value("analyst" + uniqueSuffix));
    }

    @Test
    void testUserRegistrationRejectsInvalidInput() throws Exception {
        // Missing name, invalid email, weak password
        String badPayload = """
            {
                "fullName": "",
                "email": "not-an-email",
                "username": "ab",
                "password": "123"
            }
        """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"));
    }

    @Test
    @WithMockUser(username = "analyst1", roles = {"ANALYST"})
    void testAnalystCanAccessObservabilityApis() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/traffic-stats"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "analyst1", roles = {"ANALYST"})
    void testAnalystIsForbiddenFromAdminUserManagement() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/admin/users/1/approve"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "rio10", roles = {"ADMIN"})
    void testAdminCanListAndManageUsers() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.users").isArray())
                .andExpect(jsonPath("$.total").isNumber());
    }

    @Test
    void testRegisterWithValidTeamAdminCodeGrantsActiveAdminAndAllowsLogin() throws Exception {
        String unique = String.valueOf(System.currentTimeMillis() % 100000);
        String username = "lead_admin_" + unique;
        String payload = """
            {
                "fullName": "Team Lead Administrator",
                "email": "%s@university.edu",
                "username": "%s",
                "password": "SuperSecretPassword123!",
                "adminCode": "NSM-ADMIN-2026"
            }
        """.formatted(username, username);

        // 1. Registration with valid team authorization code
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("admin_activated"))
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.username").value(username));

        // 2. Immediate login succeeds without waiting for approval
        mockMvc.perform(post("/login")
                        .param("username", username)
                        .param("password", "SuperSecretPassword123!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/"));
    }

    @Test
    void testRegisterWithInvalidAdminCodeFails() throws Exception {
        String unique = String.valueOf(System.currentTimeMillis() % 100000);
        String username = "intruder_" + unique;
        String payload = """
            {
                "fullName": "Unauthorized Attempt",
                "email": "%s@university.edu",
                "username": "%s",
                "password": "Password123!",
                "adminCode": "WRONG_SECRET_PASSKEY"
            }
        """.formatted(username, username);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Invalid Team Authorization Code")));
    }

    @Test
    void testLegacyAdminAccountIsRejected() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "admin")
                        .param("password", "admin123"))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl("/login.html?error=true"));
    }
}

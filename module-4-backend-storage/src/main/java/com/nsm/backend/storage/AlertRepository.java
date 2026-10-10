package com.nsm.backend.storage;

import com.nsm.rule.model.AlertData;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

@Repository
public class AlertRepository {

    private final JdbcTemplate jdbcTemplate;

    private final RowMapper<AlertData> rowMapper = (rs, rowNum) -> new AlertData(
            rs.getString("alert_id"),
            Instant.parse(rs.getString("timestamp")),
            rs.getString("attack_type"),
            rs.getString("severity"),
            rs.getString("src_ip"),
            rs.getString("dst_ip"),
            rs.getString("details"),
            rs.getDouble("confidence"),
            rs.getString("detection_method")
    );

    public AlertRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public synchronized void save(AlertData alert) {
        jdbcTemplate.update("""
            INSERT OR REPLACE INTO alerts (alert_id, timestamp, attack_type, severity, src_ip, dst_ip, details, confidence, detection_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
                alert.alertId(),
                alert.timestamp().toString(),
                alert.attackType(),
                alert.severity(),
                alert.srcIp(),
                alert.dstIp(),
                alert.details(),
                alert.confidence(),
                alert.detectionMethod()
        );
    }

    public List<AlertData> findRecent(int limit) {
        return jdbcTemplate.query(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                rowMapper,
                limit
        );
    }

    public Map<String, Integer> countByAttackType() {
        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("port_scan", 0);
        counts.put("brute_force", 0);
        counts.put("syn_flood", 0);

        jdbcTemplate.query(
                "SELECT attack_type, COUNT(*) as cnt FROM alerts GROUP BY attack_type",
                rs -> {
                    counts.put(rs.getString("attack_type"), rs.getInt("cnt"));
                }
        );
        return counts;
    }

    public List<Map<String, Object>> findTopSourceIps(int limit) {
        return jdbcTemplate.query(
                "SELECT src_ip, COUNT(*) as alert_count, MAX(timestamp) as last_seen FROM alerts GROUP BY src_ip ORDER BY alert_count DESC LIMIT ?",
                (rs, rowNum) -> Map.of(
                        "src_ip", rs.getString("src_ip"),
                        "alert_count", rs.getInt("alert_count"),
                        "last_seen", rs.getString("last_seen")
                ),
                limit
        );
    }

    public void clearAll() {
        jdbcTemplate.update("DELETE FROM alerts");
    }
}

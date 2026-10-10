package com.nsm.rule.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.UUID;

/**
 * Frozen Schema Contract for Alert Objects (Persons 2 & 3 -> Person 4 -> Person 5).
 */
public record AlertData(
        @JsonProperty("alert_id")
        String alertId,

        @JsonProperty("timestamp")
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
        Instant timestamp,

        @JsonProperty("attack_type")
        String attackType,

        @JsonProperty("severity")
        String severity,

        @JsonProperty("src_ip")
        String srcIp,

        @JsonProperty("dst_ip")
        String dstIp,

        @JsonProperty("details")
        String details,

        @JsonProperty("confidence")
        double confidence,

        @JsonProperty("detection_method")
        String detectionMethod
) {
    public static AlertData create(
            String attackType,
            String severity,
            String srcIp,
            String dstIp,
            String details,
            double confidence,
            String detectionMethod
    ) {
        return new AlertData(
                UUID.randomUUID().toString().substring(0, 8),
                Instant.now(),
                attackType,
                severity,
                srcIp,
                dstIp,
                details,
                confidence,
                detectionMethod != null ? detectionMethod : "rule"
        );
    }
}

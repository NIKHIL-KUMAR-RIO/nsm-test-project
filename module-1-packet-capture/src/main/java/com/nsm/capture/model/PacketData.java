package com.nsm.capture.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Frozen Schema Contract for Packet Objects (Person 1 -> Persons 2, 3, 4).
 */
public record PacketData(
        @JsonProperty("timestamp")
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
        Instant timestamp,

        @JsonProperty("src_ip")
        String srcIp,

        @JsonProperty("dst_ip")
        String dstIp,

        @JsonProperty("src_port")
        int srcPort,

        @JsonProperty("dst_port")
        int dstPort,

        @JsonProperty("protocol")
        String protocol,

        @JsonProperty("flags")
        String flags,

        @JsonProperty("length")
        int length
) {
    public static PacketData create(
            Instant timestamp,
            String srcIp,
            String dstIp,
            int srcPort,
            int dstPort,
            String protocol,
            String flags,
            int length
    ) {
        return new PacketData(
                timestamp != null ? timestamp : Instant.now(),
                srcIp,
                dstIp,
                srcPort,
                dstPort,
                protocol != null ? protocol.toUpperCase() : "TCP",
                flags != null ? flags : "",
                length
        );
    }
}

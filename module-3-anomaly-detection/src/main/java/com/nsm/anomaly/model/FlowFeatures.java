package com.nsm.anomaly.model;

/**
 * Aggregated flow-level statistical features extracted for Anomaly / ML Detection.
 */
public record FlowFeatures(
        String srcIp,
        String dstIp,
        int packetCount,
        long byteCount,
        int synCount,
        int ackCount,
        double synToAckRatio,
        int distinctDstPorts,
        double portEntropy,
        double interArrivalMeanMs,
        long durationMs
) {}

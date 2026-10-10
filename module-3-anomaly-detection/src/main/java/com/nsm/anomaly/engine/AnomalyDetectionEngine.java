package com.nsm.anomaly.engine;

import com.nsm.anomaly.extractor.FlowFeatureExtractor;
import com.nsm.anomaly.model.FlowFeatures;
import com.nsm.capture.model.PacketData;
import com.nsm.rule.model.AlertData;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Anomaly & Machine Learning Inference Engine (Person 3).
 * Evaluates statistical flow feature deviations and emits ML-tagged alerts.
 */
public class AnomalyDetectionEngine {

    private final FlowFeatureExtractor featureExtractor;
    private final Map<String, Instant> alertCooldownMap = new ConcurrentHashMap<>();
    private final int cooldownSeconds;

    public AnomalyDetectionEngine() {
        this(new FlowFeatureExtractor(5), 5);
    }

    public AnomalyDetectionEngine(FlowFeatureExtractor featureExtractor, int cooldownSeconds) {
        this.featureExtractor = featureExtractor;
        this.cooldownSeconds = cooldownSeconds;
    }

    public Optional<AlertData> evaluate(PacketData packet) {
        if (packet == null) return Optional.empty();

        FlowFeatures features = featureExtractor.updateAndExtract(packet);
        if (features == null) return Optional.empty();

        Instant now = packet.timestamp() != null ? packet.timestamp() : Instant.now();

        // 1. Port Scan Anomaly: High port entropy + elevated unique destination ports
        if (features.distinctDstPorts() >= 12 && features.portEntropy() > 2.5) {
            String key = features.srcIp() + ":ml_port_scan";
            if (isCooldownExpired(key, now)) {
                alertCooldownMap.put(key, now);
                double confidence = Math.min(0.99, 0.70 + (features.portEntropy() * 0.08));
                return Optional.of(AlertData.create(
                        "port_scan",
                        "high",
                        features.srcIp(),
                        features.dstIp(),
                        String.format("Flow Anomaly: Port Entropy=%.2f across %d unique ports",
                                features.portEntropy(), features.distinctDstPorts()),
                        Math.round(confidence * 100.0) / 100.0,
                        "ml"
                ));
            }
        }

        // 2. SYN Flood Anomaly: Extreme SYN-to-ACK imbalance with rapid arrival rate
        if (features.synCount() >= 40 && features.synToAckRatio() > 10.0 && features.interArrivalMeanMs() < 25.0) {
            String key = features.srcIp() + ":ml_syn_flood";
            if (isCooldownExpired(key, now)) {
                alertCooldownMap.put(key, now);
                return Optional.of(AlertData.create(
                        "syn_flood",
                        "high",
                        features.srcIp(),
                        features.dstIp(),
                        String.format("Flow Anomaly: SYN/ACK ratio=%.1f (Arrival interval=%.1fms)",
                                features.synToAckRatio(), features.interArrivalMeanMs()),
                        0.93,
                        "ml"
                ));
            }
        }

        // 3. Brute Force Anomaly: Sustained short connection cadence to a single destination port
        if (features.packetCount() >= 10 && features.distinctDstPorts() == 1 && features.interArrivalMeanMs() > 200.0 && features.interArrivalMeanMs() < 2000.0) {
            String key = features.srcIp() + ":ml_brute_force";
            if (isCooldownExpired(key, now)) {
                alertCooldownMap.put(key, now);
                return Optional.of(AlertData.create(
                        "brute_force",
                        "medium",
                        features.srcIp(),
                        features.dstIp(),
                        String.format("Flow Anomaly: Repetitive authentication cadence (Mean interval=%.1fms)",
                                features.interArrivalMeanMs()),
                        0.88,
                        "ml"
                ));
            }
        }

        return Optional.empty();
    }

    private boolean isCooldownExpired(String key, Instant now) {
        Instant last = alertCooldownMap.get(key);
        return last == null || Duration.between(last, now).getSeconds() >= cooldownSeconds;
    }
}

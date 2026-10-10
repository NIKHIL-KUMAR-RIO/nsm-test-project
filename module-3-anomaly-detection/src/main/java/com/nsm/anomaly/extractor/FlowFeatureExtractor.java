package com.nsm.anomaly.extractor;

import com.nsm.anomaly.model.FlowFeatures;
import com.nsm.capture.model.PacketData;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Feature Extractor: Aggregates packet streams into bidirectional flow-level metrics.
 */
public class FlowFeatureExtractor {

    private final int windowSeconds;
    private final Map<String, FlowAggregate> flowMap = new ConcurrentHashMap<>();

    public FlowFeatureExtractor() {
        this(5);
    }

    public FlowFeatureExtractor(int windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    public FlowFeatures updateAndExtract(PacketData packet) {
        if (packet == null) return null;

        String key = packet.srcIp() + "->" + packet.dstIp();
        Instant now = packet.timestamp() != null ? packet.timestamp() : Instant.now();

        FlowAggregate agg = flowMap.computeIfAbsent(key, k -> new FlowAggregate(packet.srcIp(), packet.dstIp()));
        return agg.addPacket(packet, now, windowSeconds);
    }

    private static class FlowAggregate {
        final String srcIp;
        final String dstIp;
        final List<Instant> timestamps = new ArrayList<>();
        final List<Integer> packetSizes = new ArrayList<>();
        final List<Integer> dstPorts = new ArrayList<>();
        int synCount = 0;
        int ackCount = 0;

        FlowAggregate(String srcIp, String dstIp) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
        }

        synchronized FlowFeatures addPacket(PacketData packet, Instant now, int windowSec) {
            timestamps.add(now);
            packetSizes.add(packet.length());
            dstPorts.add(packet.dstPort());

            String flags = packet.flags() != null ? packet.flags() : "";
            if (flags.contains("SYN")) synCount++;
            if (flags.contains("ACK")) ackCount++;

            // Prune older than window
            Instant cutoff = now.minusSeconds(windowSec);
            while (!timestamps.isEmpty() && timestamps.get(0).isBefore(cutoff)) {
                timestamps.remove(0);
                packetSizes.remove(0);
                dstPorts.remove(0);
            }

            int count = timestamps.size();
            long totalBytes = packetSizes.stream().mapToLong(Integer::longValue).sum();

            // Calculate inter-arrival times
            double meanInterArrivalMs = 0.0;
            if (count > 1) {
                long totalDiff = 0;
                for (int i = 1; i < count; i++) {
                    totalDiff += Duration.between(timestamps.get(i - 1), timestamps.get(i)).toMillis();
                }
                meanInterArrivalMs = (double) totalDiff / (count - 1);
            }

            // Port entropy
            Set<Integer> uniquePorts = new HashSet<>(dstPorts);
            int distinctDstPorts = uniquePorts.size();
            double entropy = calculateEntropy(dstPorts);

            double synToAckRatio = (double) synCount / Math.max(1, ackCount);
            long durationMs = count > 1 ? Duration.between(timestamps.get(0), timestamps.get(count - 1)).toMillis() : 0;

            return new FlowFeatures(
                    srcIp,
                    dstIp,
                    count,
                    totalBytes,
                    synCount,
                    ackCount,
                    synToAckRatio,
                    distinctDstPorts,
                    entropy,
                    meanInterArrivalMs,
                    durationMs
            );
        }

        private double calculateEntropy(List<Integer> ports) {
            if (ports.isEmpty()) return 0.0;
            Map<Integer, Integer> freq = new HashMap<>();
            for (int p : ports) freq.put(p, freq.getOrDefault(p, 0) + 1);

            double entropy = 0.0;
            double total = ports.size();
            for (int count : freq.values()) {
                double p = count / total;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
            return Math.round(entropy * 100.0) / 100.0;
        }
    }
}

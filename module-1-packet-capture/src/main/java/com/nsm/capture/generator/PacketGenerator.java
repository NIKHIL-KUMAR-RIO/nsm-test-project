package com.nsm.capture.generator;

import com.nsm.capture.model.PacketData;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Traffic and Attack Packet Generator for testing and single-laptop demonstrations.
 */
public class PacketGenerator {

    private final Random random = new Random();

    public List<PacketData> generatePortScan(String attackerIp, String victimIp, int startPort, int endPort) {
        List<PacketData> list = new ArrayList<>();
        Instant now = Instant.now();
        for (int p = startPort; p <= endPort; p++) {
            list.add(PacketData.create(
                    now.plusMillis((long) (p - startPort) * 40),
                    attackerIp,
                    victimIp,
                    40000 + random.nextInt(20000),
                    p,
                    "TCP",
                    "SYN",
                    60
            ));
        }
        return list;
    }

    public List<PacketData> generateSynFlood(String attackerIp, String victimIp, int targetPort, int count) {
        List<PacketData> list = new ArrayList<>();
        Instant now = Instant.now();
        for (int i = 0; i < count; i++) {
            list.add(PacketData.create(
                    now.plusMillis(i * 10),
                    attackerIp,
                    victimIp,
                    30000 + (i % 30000),
                    targetPort,
                    "TCP",
                    "SYN",
                    60
            ));
        }
        return list;
    }

    public List<PacketData> generateBruteForce(String attackerIp, String victimIp, int servicePort, int attempts) {
        List<PacketData> list = new ArrayList<>();
        Instant now = Instant.now();
        for (int i = 0; i < attempts; i++) {
            list.add(PacketData.create(
                    now.plusMillis((long) i * 800),
                    attackerIp,
                    victimIp,
                    50000 + i,
                    servicePort,
                    "TCP",
                    "SYN",
                    60
            ));
        }
        return list;
    }

    public List<PacketData> generateBenignTraffic(int count) {
        List<PacketData> list = new ArrayList<>();
        Instant now = Instant.now();
        for (int i = 0; i < count; i++) {
            String clientIp = "192.168.1." + (10 + random.nextInt(30));
            int dstPort = random.nextBoolean() ? 80 : 443;
            list.add(PacketData.create(
                    now.plusMillis(i * 100),
                    clientIp,
                    "104.21.45.10",
                    40000 + random.nextInt(20000),
                    dstPort,
                    "TCP",
                    "ACK",
                    128 + random.nextInt(1000)
            ));
        }
        return list;
    }
}

package com.nsm.backend.service;

import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Service
@EnableScheduling
public class TrafficStatsService {

    private static final int HISTORY_POINTS = 30;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final AtomicLong packetCounter = new AtomicLong(0);
    private long lastPacketCount = 0;

    private final List<Integer> packetsPerSecList = Collections.synchronizedList(new ArrayList<>());
    private final List<String> timestampsList = Collections.synchronizedList(new ArrayList<>());

    public TrafficStatsService() {
        LocalTime now = LocalTime.now();
        for (int i = HISTORY_POINTS; i >= 1; i--) {
            timestampsList.add(now.minusSeconds(i).format(TIME_FORMAT));
            packetsPerSecList.add(0);
        }
    }

    public void incrementPacket() {
        packetCounter.incrementAndGet();
    }

    public void incrementPacketBatch(int count) {
        packetCounter.addAndGet(count);
    }

    @Scheduled(fixedRate = 1000)
    public void recordSecondTick() {
        long current = packetCounter.get();
        int diff = (int) (current - lastPacketCount);
        lastPacketCount = current;

        String timeStr = LocalTime.now().format(TIME_FORMAT);

        synchronized (packetsPerSecList) {
            packetsPerSecList.add(diff);
            timestampsList.add(timeStr);

            while (packetsPerSecList.size() > HISTORY_POINTS) {
                packetsPerSecList.remove(0);
                timestampsList.remove(0);
            }
        }
    }

    public Map<String, Object> getTrafficStats() {
        synchronized (packetsPerSecList) {
            return Map.of(
                    "packets_per_sec", new ArrayList<>(packetsPerSecList),
                    "timestamps", new ArrayList<>(timestampsList)
            );
        }
    }

    public long getTotalPackets() {
        return packetCounter.get();
    }
}

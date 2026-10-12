package com.nsm.backend.service;

import com.nsm.anomaly.engine.AnomalyDetectionEngine;
import com.nsm.backend.storage.AlertRepository;
import com.nsm.capture.generator.PacketGenerator;
import com.nsm.capture.model.PacketData;
import com.nsm.capture.parser.PcapBinaryParser;
import com.nsm.capture.probe.LiveDecoyProbeListener;
import com.nsm.rule.engine.RuleEngine;
import com.nsm.rule.model.AlertData;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Connective Tissue & Pipeline Coordinator (Person 4):
 * Ties together Module 1 (Capture), Module 2 (Rules), Module 3 (Anomaly/ML), and Module 4 (Storage).
 */
@Service
public class NsmPipelineCoordinator {

    private static final Logger log = LoggerFactory.getLogger(NsmPipelineCoordinator.class);

    private final AlertRepository alertRepository;
    private final TrafficStatsService trafficStatsService;
    private final RuleEngine ruleEngine;
    private final AnomalyDetectionEngine anomalyEngine;
    private final PacketGenerator packetGenerator;
    private final PcapBinaryParser pcapParser;

    private LiveDecoyProbeListener decoyProbeListener;
    private final ScheduledExecutorService simulationExecutor = Executors.newSingleThreadScheduledExecutor();
    private final Random random = new Random();

    @Value("${nsm.probe.enabled:true}")
    private boolean probeEnabled;

    @Value("${nsm.probe.ports:2222,8088,8888,9090}")
    private String probePorts;

    @Value("${nsm.simulation.enabled:true}")
    private boolean simulationEnabled;

    public NsmPipelineCoordinator(
            AlertRepository alertRepository,
            TrafficStatsService trafficStatsService
    ) {
        this.alertRepository = alertRepository;
        this.trafficStatsService = trafficStatsService;
        this.ruleEngine = new RuleEngine();
        this.anomalyEngine = new AnomalyDetectionEngine();
        this.packetGenerator = new PacketGenerator();
        this.pcapParser = new PcapBinaryParser();
    }

    @PostConstruct
    public void init() {
        // 1. Start Live Decoy Honeypot Listener (Mode A: Live Network)
        if (probeEnabled) {
            List<Integer> ports = Arrays.stream(probePorts.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(Integer::parseInt)
                    .toList();
            decoyProbeListener = new LiveDecoyProbeListener(ports, this::processIncomingPacket);
            decoyProbeListener.start();
            log.info("🛡️ Live Decoy Probe active on ports: {}", ports);
        }

        // 2. Start Background Benign Traffic Simulation
        if (simulationEnabled) {
            simulationExecutor.scheduleAtFixedRate(this::generateBenignPulse, 1, 1, TimeUnit.SECONDS);
            log.info("🌐 Background benign traffic generator active.");
        }
    }

    public void processIncomingPacket(PacketData packet) {
        if (packet == null) return;
        trafficStatsService.incrementPacket();

        // Evaluate Rule Engine (Module 2)
        List<AlertData> ruleAlerts = ruleEngine.evaluate(packet);
        for (AlertData alert : ruleAlerts) {
            alertRepository.save(alert);
            log.warn("🚨 [RULE ALERT] {} from {} -> {} [Severity: {}]",
                    alert.attackType(), alert.srcIp(), alert.dstIp(), alert.severity());
        }

        // Evaluate Anomaly & ML Engine (Module 3)
        Optional<AlertData> mlAlertOpt = anomalyEngine.evaluate(packet);
        if (mlAlertOpt.isPresent()) {
            AlertData mlAlert = mlAlertOpt.get();
            alertRepository.save(mlAlert);
            log.warn("🧠 [ML ALERT] {} from {} -> {} [Confidence: {}]",
                    mlAlert.attackType(), mlAlert.srcIp(), mlAlert.dstIp(), mlAlert.confidence());
        }
    }

    private void generateBenignPulse() {
        Thread.ofVirtual().start(() -> {
            List<PacketData> benign = packetGenerator.generateBenignTraffic(5 + random.nextInt(10));
            for (PacketData p : benign) {
                processIncomingPacket(p);
            }
        });
    }

    // --- Attack Simulation Triggers (Single-Laptop Mode) ---

    public void triggerPortScan(String attackerIp, String victimIp, int startPort, int endPort) {
        log.info("Launching simulated Port Scan from {} targeting ports {}-{}", attackerIp, startPort, endPort);
        List<PacketData> packets = packetGenerator.generatePortScan(attackerIp, victimIp, startPort, endPort);
        for (PacketData p : packets) {
            processIncomingPacket(p);
        }
    }

    public void triggerSynFlood(String attackerIp, String victimIp, int targetPort, int count) {
        log.info("Launching simulated SYN Flood ({} packets) from {} -> Port {}", count, attackerIp, targetPort);
        List<PacketData> packets = packetGenerator.generateSynFlood(attackerIp, victimIp, targetPort, count);
        for (PacketData p : packets) {
            processIncomingPacket(p);
        }
    }

    public void triggerBruteForce(String attackerIp, String victimIp, int servicePort, int attempts) {
        log.info("Launching simulated Brute Force ({} attempts) from {} -> Port {}", attempts, attackerIp, servicePort);
        List<PacketData> packets = packetGenerator.generateBruteForce(attackerIp, victimIp, servicePort, attempts);
        for (PacketData p : packets) {
            processIncomingPacket(p);
        }
    }

    public int replayPcapStream(InputStream in) throws Exception {
        List<PacketData> packets = pcapParser.parseAll(in);
        Thread.ofVirtual().start(() -> {
            log.info("Replaying {} packets from PCAP capture...", packets.size());
            for (PacketData p : packets) {
                processIncomingPacket(p);
                try { Thread.sleep(15); } catch (InterruptedException ignored) {}
            }
        });
        return packets.size();
    }

    public void resetEngines() {
        ruleEngine.reset();
        log.info("🧹 Detection engines and cooldown state reset.");
    }

    @PreDestroy
    public void cleanup() {
        if (decoyProbeListener != null) {
            decoyProbeListener.stop();
        }
        simulationExecutor.shutdownNow();
    }
}

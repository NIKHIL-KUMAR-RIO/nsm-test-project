package com.nsm.capture.probe;

import com.nsm.capture.model.PacketData;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Live Network Decoy Probe Listener:
 * Intercepts real inbound connection probes across designated decoy ports from any machine on the LAN.
 */
public class LiveDecoyProbeListener {

    private final List<Integer> ports;
    private final Consumer<PacketData> packetConsumer;
    private final List<ServerSocket> serverSockets = new ArrayList<>();
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = false;

    public LiveDecoyProbeListener(List<Integer> ports, Consumer<PacketData> packetConsumer) {
        this.ports = ports;
        this.packetConsumer = packetConsumer;
    }

    public synchronized void start() {
        if (running) return;
        running = true;

        for (int port : ports) {
            executor.submit(() -> listenOnPort(port));
        }
    }

    private void listenOnPort(int port) {
        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("0.0.0.0", port));
            synchronized (serverSockets) {
                serverSockets.add(serverSocket);
            }

            while (running && !serverSocket.isClosed()) {
                try {
                    Socket socket = serverSocket.accept();
                    String remoteIp = socket.getInetAddress().getHostAddress();
                    if ("0:0:0:0:0:0:0:1".equals(remoteIp) || "::1".equals(remoteIp)) {
                        remoteIp = "127.0.0.1";
                    }
                    int remotePort = socket.getPort();
                    String localIp = socket.getLocalAddress().getHostAddress();
                    if ("0:0:0:0:0:0:0:1".equals(localIp) || "::1".equals(localIp)) {
                        localIp = "127.0.0.1";
                    }

                    PacketData packet = PacketData.create(
                            Instant.now(),
                            remoteIp,
                            localIp,
                            remotePort,
                            port,
                            "TCP",
                            "SYN",
                            60
                    );

                    packetConsumer.accept(packet);
                    socket.close();
                } catch (IOException e) {
                    if (!running) break;
                }
            }
        } catch (Exception ignored) {
        }
    }

    public synchronized void stop() {
        running = false;
        synchronized (serverSockets) {
            for (ServerSocket ss : serverSockets) {
                try {
                    ss.close();
                } catch (IOException ignored) {}
            }
            serverSockets.clear();
        }
        executor.shutdownNow();
    }
}

package com.nsm.capture.emitter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nsm.capture.model.PacketData;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;

/**
 * Output Emitter: writes Packet JSON to .jsonl file or pushes via HTTP POST to Module 4.
 */
public class PacketStreamEmitter {

    private final ObjectMapper mapper;
    private final HttpClient httpClient;

    public PacketStreamEmitter() {
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
        this.httpClient = HttpClient.newHttpClient();
    }

    public void writeToJsonl(List<PacketData> packets, Path outputPath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath.toFile()))) {
            for (PacketData p : packets) {
                writer.write(mapper.writeValueAsString(p));
                writer.newLine();
            }
        }
    }

    public boolean sendHttpPacket(PacketData packet, String targetUrl) {
        try {
            String json = mapper.writeValueAsString(packet);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception e) {
            return false;
        }
    }

    public ObjectMapper getMapper() {
        return mapper;
    }
}

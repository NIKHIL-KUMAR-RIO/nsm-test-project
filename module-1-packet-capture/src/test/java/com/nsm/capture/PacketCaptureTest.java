package com.nsm.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nsm.capture.generator.PacketGenerator;
import com.nsm.capture.model.PacketData;
import com.nsm.capture.parser.PcapBinaryParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PacketCaptureTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
    }

    @Test
    void testPacketDataMatchesFrozenJsonSchema() throws Exception {
        PacketData packet = PacketData.create(
                Instant.parse("2026-09-18T10:32:01.123Z"),
                "192.168.1.5",
                "10.0.0.1",
                443,
                22,
                "TCP",
                "SYN",
                60
        );

        String json = mapper.writeValueAsString(packet);
        JsonNode node = mapper.readTree(json);

        // Verify exact frozen schema fields
        assertTrue(node.has("timestamp"));
        assertTrue(node.has("src_ip"));
        assertTrue(node.has("dst_ip"));
        assertTrue(node.has("src_port"));
        assertTrue(node.has("dst_port"));
        assertTrue(node.has("protocol"));
        assertTrue(node.has("flags"));
        assertTrue(node.has("length"));

        assertEquals("192.168.1.5", node.get("src_ip").asText());
        assertEquals("10.0.0.1", node.get("dst_ip").asText());
        assertEquals(443, node.get("src_port").asInt());
        assertEquals(22, node.get("dst_port").asInt());
        assertEquals("TCP", node.get("protocol").asText());
        assertEquals("SYN", node.get("flags").asText());
        assertEquals(60, node.get("length").asInt());
    }

    @Test
    void testPcapBinaryParserDissectsFrame() throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(24 + 16 + 54);
        buf.order(ByteOrder.BIG_ENDIAN);

        // Global Header (24 bytes)
        buf.putInt(0xA1B2C3D4);
        buf.putShort((short) 2);
        buf.putShort((short) 4);
        buf.putInt(0);
        buf.putInt(0);
        buf.putInt(65535);
        buf.putInt(1);

        // Packet Header (16 bytes)
        buf.putInt(1700000000);
        buf.putInt(50000);
        buf.putInt(54);
        buf.putInt(54);

        // Frame: Eth (14) + IPv4 (20) + TCP (20)
        buf.put(new byte[12]);
        buf.putShort((short) 0x0800); // IPv4
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) 40);
        buf.putShort((short) 1);
        buf.putShort((short) 0);
        buf.put((byte) 64);
        buf.put((byte) 6); // TCP
        buf.putShort((short) 0);
        buf.put(new byte[]{ (byte) 192, (byte) 168, 1, 5 });
        buf.put(new byte[]{ 10, 0, 0, 1 });
        buf.putShort((short) 443);
        buf.putShort((short) 22);
        buf.putInt(100);
        buf.putInt(0);
        buf.putShort((short) 0x5002); // SYN
        buf.putShort((short) 8192);
        buf.putShort((short) 0);
        buf.putShort((short) 0);

        PcapBinaryParser parser = new PcapBinaryParser();
        List<PacketData> packets = parser.parseAll(new ByteArrayInputStream(buf.array()));

        assertEquals(1, packets.size());
        PacketData p = packets.get(0);
        assertEquals("192.168.1.5", p.srcIp());
        assertEquals("10.0.0.1", p.dstIp());
        assertEquals(443, p.srcPort());
        assertEquals(22, p.dstPort());
        assertEquals("TCP", p.protocol());
        assertEquals("SYN", p.flags());
    }

    @Test
    void testPacketGeneratorGeneratesAttacks() {
        PacketGenerator gen = new PacketGenerator();
        List<PacketData> portScan = gen.generatePortScan("192.168.1.50", "192.168.1.100", 20, 40);
        assertEquals(21, portScan.size());
        assertEquals(20, portScan.get(0).dstPort());
        assertEquals(40, portScan.get(20).dstPort());

        List<PacketData> synFlood = gen.generateSynFlood("192.168.1.99", "192.168.1.100", 80, 50);
        assertEquals(50, synFlood.size());
    }
}

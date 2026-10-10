package com.nsm.capture.parser;

import com.nsm.capture.model.PacketData;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Pure Java binary reader for standard libpcap (.pcap) files.
 * Dissects Ethernet, IPv4, TCP (with flags), UDP, and ICMP.
 */
public class PcapBinaryParser {

    private static final int PCAP_MAGIC_BIG_ENDIAN = 0xA1B2C3D4;
    private static final int PCAP_MAGIC_LITTLE_ENDIAN = 0xD4C3B2A1;
    private static final int PCAP_MAGIC_NANO_BE = 0xA1B23C4D;
    private static final int PCAP_MAGIC_NANO_LE = 0x4D3CB2A1;

    public List<PacketData> parseAll(InputStream in) throws Exception {
        List<PacketData> packets = new ArrayList<>();
        streamPackets(in, packets::add);
        return packets;
    }

    public void streamPackets(InputStream in, Consumer<PacketData> packetConsumer) throws Exception {
        byte[] allBytes = in.readAllBytes();
        if (allBytes.length < 24) {
            throw new IllegalArgumentException("Invalid PCAP file: under 24 bytes global header.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(allBytes);
        int magic = buffer.getInt();

        ByteOrder byteOrder;
        if (magic == PCAP_MAGIC_BIG_ENDIAN || magic == PCAP_MAGIC_NANO_BE) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magic == PCAP_MAGIC_LITTLE_ENDIAN || magic == PCAP_MAGIC_NANO_LE) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            throw new IllegalArgumentException(String.format("Unsupported PCAP magic number: 0x%08X", magic));
        }
        buffer.order(byteOrder);

        buffer.getShort(); // major
        buffer.getShort(); // minor
        buffer.getInt();   // thiszone
        buffer.getInt();   // sigfigs
        int snaplen = buffer.getInt();
        buffer.getInt(); // network: link-layer header type (1 = LINKTYPE_ETHERNET)

        while (buffer.remaining() >= 16) {
            long tsSec = Integer.toUnsignedLong(buffer.getInt());
            long tsUsec = Integer.toUnsignedLong(buffer.getInt());
            int inclLen = buffer.getInt();
            buffer.getInt(); // origLen: actual length of packet on wire

            if (inclLen <= 0 || inclLen > snaplen + 65535 || inclLen > buffer.remaining()) {
                break;
            }

            byte[] frameBytes = new byte[inclLen];
            buffer.get(frameBytes);

            Instant timestamp = Instant.ofEpochSecond(tsSec, tsUsec * 1000);
            PacketData packet = dissectFrame(frameBytes, timestamp);
            if (packet != null) {
                packetConsumer.accept(packet);
            }
        }
    }

    public PacketData dissectFrame(byte[] frame, Instant timestamp) {
        if (frame == null || frame.length < 14) return null;

        ByteBuffer bb = ByteBuffer.wrap(frame);
        bb.position(12);
        int etherType = Short.toUnsignedInt(bb.getShort());

        if (etherType != 0x0800) {
            // Non-IPv4 (ARP, IPv6, etc.)
            return null;
        }

        if (bb.remaining() < 20) return null;

        int ipStart = bb.position();
        byte verAndIhl = bb.get();
        int ihl = (verAndIhl & 0x0F) * 4;
        bb.get(); // DSCP
        int totalLength = Short.toUnsignedInt(bb.getShort());
        bb.getShort(); // ID
        bb.getShort(); // Flags/Frag
        bb.get();      // TTL
        int protocolNum = Byte.toUnsignedInt(bb.get());
        bb.getShort(); // Checksum

        byte[] srcIpBytes = new byte[4];
        bb.get(srcIpBytes);
        String srcIp = formatIp(srcIpBytes);

        byte[] dstIpBytes = new byte[4];
        bb.get(dstIpBytes);
        String dstIp = formatIp(dstIpBytes);

        bb.position(ipStart + ihl);

        if (protocolNum == 6) { // TCP
            if (bb.remaining() < 20) return null;
            int srcPort = Short.toUnsignedInt(bb.getShort());
            int dstPort = Short.toUnsignedInt(bb.getShort());
            bb.getInt(); // Seq
            bb.getInt(); // Ack
            int dataOffsetAndFlags = Short.toUnsignedInt(bb.getShort());
            int flagsByte = dataOffsetAndFlags & 0x01FF;
            String flagsStr = formatTcpFlags(flagsByte);

            return PacketData.create(timestamp, srcIp, dstIp, srcPort, dstPort, "TCP", flagsStr, totalLength);
        } else if (protocolNum == 17) { // UDP
            if (bb.remaining() < 8) return null;
            int srcPort = Short.toUnsignedInt(bb.getShort());
            int dstPort = Short.toUnsignedInt(bb.getShort());
            int udpLen = Short.toUnsignedInt(bb.getShort());
            return PacketData.create(timestamp, srcIp, dstIp, srcPort, dstPort, "UDP", "", udpLen);
        } else if (protocolNum == 1) { // ICMP
            return PacketData.create(timestamp, srcIp, dstIp, 0, 0, "ICMP", "", totalLength);
        }

        return null;
    }

    private String formatIp(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    private String formatTcpFlags(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x02) != 0) sb.append("SYN ");
        if ((flags & 0x10) != 0) sb.append("ACK ");
        if ((flags & 0x01) != 0) sb.append("FIN ");
        if ((flags & 0x04) != 0) sb.append("RST ");
        if ((flags & 0x08) != 0) sb.append("PSH ");
        if ((flags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim();
    }
}

package com.nishant.packetanalyzer.parser;

import static com.nishant.packetanalyzer.parser.NetConstants.*;
import static com.nishant.packetanalyzer.util.Bytes.*;

import com.nishant.packetanalyzer.pcap.RawPacket;
import java.util.Optional;

/**
 * Walks through a raw Ethernet frame and extracts the header fields.
 *
 * <pre>
 *  | Ethernet 14 B | IPv4 20-60 B | TCP 20-60 B  or  UDP 8 B | payload ... |
 * </pre>
 *
 * Every step checks that enough bytes are left, so a damaged or truncated packet makes
 * {@link #parse} return an empty Optional instead of crashing.
 */
public final class PacketParser {
    private static final int ETH_HEADER_LEN = 14;
    private static final int MIN_IP_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {}

    /**
     * Parses one packet.
     *
     * @return the parsed packet, or empty if the packet is malformed / too short
     */
    public static Optional<ParsedPacket> parse(RawPacket raw) {
        byte[] d = raw.data();
        int len = d.length;

        ParsedPacket p = new ParsedPacket();
        p.tsSec = raw.tsSec();
        p.tsUsec = raw.tsUsec();

        // ---- Layer 2: Ethernet ----
        if (len < ETH_HEADER_LEN) {
            return Optional.empty();
        }
        p.dstMac = macToString(d, 0);
        p.srcMac = macToString(d, 6);
        p.etherType = u16(d, 12);
        int offset = ETH_HEADER_LEN;
        int end = len; // where the packet's real data ends (Ethernet may add padding bytes after it)

        if (p.etherType == ETHERTYPE_IPV4) {
            // ---- Layer 3: IPv4 ----
            if (len < offset + MIN_IP_HEADER_LEN) {
                return Optional.empty();
            }
            int versionAndIhl = u8(d, offset);
            p.ipVersion = versionAndIhl >>> 4;
            int ipHeaderLen = (versionAndIhl & 0x0F) * 4; // IHL is counted in 4-byte words
            if (p.ipVersion != 4 || ipHeaderLen < MIN_IP_HEADER_LEN || len < offset + ipHeaderLen) {
                return Optional.empty();
            }
            int totalLength = u16(d, offset + 2);
            if (totalLength >= ipHeaderLen) {
                end = Math.min(len, offset + totalLength); // ignore Ethernet padding after the IP packet
            }
            int fragmentOffset = u16(d, offset + 6) & 0x1FFF;
            p.ttl = u8(d, offset + 8);
            p.protocol = u8(d, offset + 9);
            p.srcIp = i32(d, offset + 12);
            p.dstIp = i32(d, offset + 16);
            p.hasIp = true;
            offset += ipHeaderLen;

            // ---- Layer 4: TCP / UDP (only the first fragment of a packet carries this header) ----
            if (fragmentOffset == 0) {
                if (p.protocol == PROTO_TCP) {
                    offset = parseTcp(d, offset, end, p);
                } else if (p.protocol == PROTO_UDP) {
                    offset = parseUdp(d, offset, end, p);
                }
                if (offset < 0) {
                    return Optional.empty();
                }
            }
        }

        if (offset < end) {
            p.payloadOffset = offset;
            p.payloadLength = end - offset;
        }
        return Optional.of(p);
    }

    /** Returns the offset just after the TCP header, or -1 if the header is invalid. */
    private static int parseTcp(byte[] d, int off, int end, ParsedPacket p) {
        if (end < off + MIN_TCP_HEADER_LEN) {
            return -1;
        }
        int tcpHeaderLen = (u8(d, off + 12) >>> 4) * 4; // data offset field, in 4-byte words
        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || end < off + tcpHeaderLen) {
            return -1;
        }
        p.srcPort = u16(d, off);
        p.dstPort = u16(d, off + 2);
        p.seqNumber = u32(d, off + 4);
        p.ackNumber = u32(d, off + 8);
        p.tcpFlags = u8(d, off + 13);
        p.hasTcp = true;
        return off + tcpHeaderLen;
    }

    /** Returns the offset just after the UDP header, or -1 if the header is invalid. */
    private static int parseUdp(byte[] d, int off, int end, ParsedPacket p) {
        if (end < off + UDP_HEADER_LEN) {
            return -1;
        }
        p.srcPort = u16(d, off);
        p.dstPort = u16(d, off + 2);
        p.hasUdp = true;
        return off + UDP_HEADER_LEN;
    }

    // ------------------------------------------------------------------
    // Helpers that turn numbers into readable text
    // ------------------------------------------------------------------

    public static String macToString(byte[] d, int off) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", u8(d, off + i)));
        }
        return sb.toString();
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTO_ICMP -> "ICMP";
            case PROTO_TCP -> "TCP";
            case PROTO_UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        return sb.length() == 0 ? "none" : sb.toString().trim();
    }
}

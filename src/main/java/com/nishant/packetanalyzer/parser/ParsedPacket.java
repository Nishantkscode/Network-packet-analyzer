package com.nishant.packetanalyzer.parser;

import com.nishant.packetanalyzer.util.IpUtils;

/**
 * Human-readable view of one packet, filled in by {@link PacketParser}.
 * Think of it as the packet "unwrapped" layer by layer: Ethernet, then IP, then TCP/UDP, then payload.
 */
public final class ParsedPacket {
    // Timestamps
    public long tsSec;
    public long tsUsec;

    // Ethernet layer
    public String srcMac;
    public String dstMac;
    public int etherType;

    // IP layer (only if hasIp)
    public boolean hasIp;
    public int ipVersion;
    public int srcIp;          // 32-bit address, e.g. 0xC0A80164 = 192.168.1.100
    public int dstIp;
    public int protocol;       // TCP=6, UDP=17, ICMP=1
    public int ttl;

    // Transport layer
    public boolean hasTcp;
    public boolean hasUdp;
    public int srcPort;
    public int dstPort;

    // TCP only
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload = the application data after all headers (e.g. a TLS Client Hello or an HTTP request).
    // Instead of a C++ pointer we keep an index into the original packet bytes.
    public int payloadOffset;
    public int payloadLength;

    public String srcIpString() {
        return IpUtils.toString(srcIp);
    }

    public String dstIpString() {
        return IpUtils.toString(dstIp);
    }
}

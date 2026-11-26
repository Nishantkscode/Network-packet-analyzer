package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.dpi.FiveTuple;
import com.nishant.packetanalyzer.parser.ParsedPacket;
import com.nishant.packetanalyzer.pcap.RawPacket;

/**
 * Everything a worker thread needs to know about one packet. Self-contained: it holds the packet
 * bytes itself, so it can safely travel between threads through the queues.
 */
public record PacketJob(long id, long tsSec, long tsUsec, FiveTuple tuple, byte[] data,
                        int payloadOffset, int payloadLength) {

    /**
     * Builds a job from a parsed packet, or returns null if the packet is not IPv4 TCP/UDP
     * (those packets are skipped, as in the original program).
     */
    public static PacketJob from(long id, RawPacket raw, ParsedPacket p) {
        if (!p.hasIp || (!p.hasTcp && !p.hasUdp)) {
            return null;
        }
        FiveTuple tuple = new FiveTuple(p.srcIp, p.dstIp, p.srcPort, p.dstPort, p.protocol);
        return new PacketJob(id, raw.tsSec(), raw.tsUsec(), tuple, raw.data(), p.payloadOffset, p.payloadLength);
    }
}

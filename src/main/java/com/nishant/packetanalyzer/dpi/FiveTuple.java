package com.nishant.packetanalyzer.dpi;

import static com.nishant.packetanalyzer.parser.NetConstants.PROTO_TCP;
import static com.nishant.packetanalyzer.parser.NetConstants.PROTO_UDP;

import com.nishant.packetanalyzer.util.IpUtils;

/**
 * The five values that identify one network connection ("flow"):
 * source IP, destination IP, source port, destination port and protocol.
 *
 * All packets with the same five-tuple belong to the same conversation. As a Java record,
 * equals() and hashCode() are generated automatically, so it works as a HashMap key.
 */
public record FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {

    /** The same connection seen from the other side (server to client). */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * A well-mixed, non-negative hash used to spread flows over worker threads.
     * Same tuple always gives the same value, so all packets of a flow reach the same thread.
     */
    public int flowHash() {
        int h = 0;
        h = mix(h, srcIp);
        h = mix(h, dstIp);
        h = mix(h, srcPort);
        h = mix(h, dstPort);
        h = mix(h, protocol);
        return h & 0x7FFFFFFF;
    }

    private static int mix(int h, int value) {
        return h ^ (value + 0x9e3779b9 + (h << 6) + (h >>> 2));
    }

    public String protocolName() {
        return protocol == PROTO_TCP ? "TCP" : protocol == PROTO_UDP ? "UDP" : "?";
    }

    @Override
    public String toString() {
        return IpUtils.toString(srcIp) + ":" + srcPort + " -> "
                + IpUtils.toString(dstIp) + ":" + dstPort + " (" + protocolName() + ")";
    }
}

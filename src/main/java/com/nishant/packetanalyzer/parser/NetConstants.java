package com.nishant.packetanalyzer.parser;

/** Well-known protocol numbers and flag bits (the C++ namespaces Protocol, EtherType and TCPFlags). */
public final class NetConstants {
    private NetConstants() {}

    // EtherType values (what comes after the Ethernet header)
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_ARP = 0x0806;
    public static final int ETHERTYPE_IPV6 = 0x86DD;

    // IP protocol numbers (what comes after the IP header)
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    // TCP flag bits
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;
}

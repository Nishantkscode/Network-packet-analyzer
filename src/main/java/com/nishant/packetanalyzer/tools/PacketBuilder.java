package com.nishant.packetanalyzer.tools;

import com.nishant.packetanalyzer.util.IpUtils;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Builds raw packets byte by byte. Used to create sample captures and test data.
 * Seeing how a packet is BUILT is a good way to understand how it is PARSED.
 */
public final class PacketBuilder {
    private PacketBuilder() {}

    /** Small helper for writing big-endian numbers into a growing byte array. */
    private static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer u8(int v) {
            out.write(v & 0xFF);
            return this;
        }

        Writer u16(int v) {
            return u8(v >>> 8).u8(v);
        }

        Writer u24(int v) {
            return u8(v >>> 16).u16(v);
        }

        Writer u32(long v) {
            return u16((int) (v >>> 16)).u16((int) v);
        }

        Writer bytes(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        byte[] done() {
            return out.toByteArray();
        }
    }

    public static byte[] concat(byte[]... parts) {
        Writer w = new Writer();
        for (byte[] p : parts) w.bytes(p);
        return w.done();
    }

    private static byte[] mac(String text) {
        String[] parts = text.split(":");
        byte[] b = new byte[6];
        for (int i = 0; i < 6; i++) b[i] = (byte) Integer.parseInt(parts[i], 16);
        return b;
    }

    /** Ethernet header: destination MAC, source MAC, EtherType (14 bytes). */
    public static byte[] ethernet(String srcMac, String dstMac, int etherType) {
        return new Writer().bytes(mac(dstMac)).bytes(mac(srcMac)).u16(etherType).done();
    }

    /** IPv4 header without options (20 bytes) with a correct header checksum. */
    public static byte[] ipv4(String srcIp, String dstIp, int protocol, int payloadLen, Random rnd) {
        byte[] header = new Writer()
                .u8(0x45)                       // version 4, header length 5 words
                .u8(0)                          // type of service
                .u16(20 + payloadLen)           // total length
                .u16(1 + rnd.nextInt(65535))    // identification
                .u16(0x4000)                    // flags: don't fragment
                .u8(64)                         // TTL
                .u8(protocol)
                .u16(0)                         // checksum placeholder
                .u32(IpUtils.parse(srcIp) & 0xFFFFFFFFL)
                .u32(IpUtils.parse(dstIp) & 0xFFFFFFFFL)
                .done();
        int checksum = checksum(header);
        header[10] = (byte) (checksum >>> 8);
        header[11] = (byte) checksum;
        return header;
    }

    /** Standard Internet checksum: ones' complement sum of 16-bit words. */
    private static int checksum(byte[] b) {
        long sum = 0;
        for (int i = 0; i + 1 < b.length; i += 2) {
            sum += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
        }
        while ((sum >>> 16) != 0) sum = (sum & 0xFFFF) + (sum >>> 16);
        return (int) (~sum & 0xFFFF);
    }

    /** TCP header without options (20 bytes). */
    public static byte[] tcp(int srcPort, int dstPort, long seq, long ack, int flags) {
        return new Writer().u16(srcPort).u16(dstPort).u32(seq).u32(ack)
                .u8(5 << 4)                     // header length 5 words
                .u8(flags)
                .u16(65535)                     // window
                .u16(0)                         // checksum (left 0 in test data)
                .u16(0)                         // urgent pointer
                .done();
    }

    /** UDP header (8 bytes). */
    public static byte[] udp(int srcPort, int dstPort, int payloadLen) {
        return new Writer().u16(srcPort).u16(dstPort).u16(8 + payloadLen).u16(0).done();
    }

    /** A TLS Client Hello record whose SNI extension carries {@code sni}. */
    public static byte[] tlsClientHello(String sni, Random rnd) {
        byte[] name = sni.getBytes(StandardCharsets.US_ASCII);

        byte[] sniEntry = new Writer().u8(0).u16(name.length).bytes(name).done();
        byte[] sniList = new Writer().u16(sniEntry.length).bytes(sniEntry).done();
        byte[] sniExt = new Writer().u16(0x0000).u16(sniList.length).bytes(sniList).done();
        byte[] supportedVersions = new Writer().u16(0x002b).u16(3).u8(2).u16(0x0304).done();
        byte[] extensions = concat(sniExt, supportedVersions);

        byte[] random = new byte[32];
        rnd.nextBytes(random);
        byte[] body = new Writer()
                .u16(0x0303)                                   // client version TLS 1.2
                .bytes(random)
                .u8(0)                                         // session id length
                .u16(4).u16(0x1301).u16(0x1302)                // two cipher suites
                .u8(1).u8(0)                                   // compression: null only
                .u16(extensions.length).bytes(extensions)
                .done();

        byte[] handshake = new Writer().u8(0x01).u24(body.length).bytes(body).done();
        return new Writer().u8(0x16).u16(0x0301).u16(handshake.length).bytes(handshake).done();
    }

    public static byte[] httpRequest(String host) {
        return ("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] dnsQuery(String domain, Random rnd) {
        Writer w = new Writer()
                .u16(1 + rnd.nextInt(65535))    // transaction id
                .u16(0x0100)                    // flags: standard query
                .u16(1).u16(0).u16(0).u16(0);   // 1 question, no other records
        for (String label : domain.split("\\.")) {
            w.u8(label.length()).bytes(label.getBytes(StandardCharsets.US_ASCII));
        }
        return w.u8(0).u16(1).u16(1).done();    // end of name, type A, class IN
    }
}

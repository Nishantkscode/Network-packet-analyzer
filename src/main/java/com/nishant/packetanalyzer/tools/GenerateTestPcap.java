package com.nishant.packetanalyzer.tools;

import static com.nishant.packetanalyzer.parser.NetConstants.*;
import static com.nishant.packetanalyzer.tools.PacketBuilder.*;

import com.nishant.packetanalyzer.pcap.PcapGlobalHeader;
import com.nishant.packetanalyzer.pcap.PcapWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;

/**
 * Creates a sample capture with TLS (HTTPS) connections, plain HTTP, DNS queries and some
 * traffic from a "bad" IP, so the analyzer and the blocking rules can be tried without Wireshark.
 * Java port of generate_test_pcap.py (the random generator is seeded, so the file is the same every run).
 */
public final class GenerateTestPcap {
    private record Site(String ip, String name, int port) {}

    private static final String USER_MAC = "00:11:22:33:44:55";
    private static final String GATEWAY_MAC = "aa:bb:cc:dd:ee:ff";
    private static final String USER_IP = "192.168.1.100";
    private static final String BLOCKED_SOURCE_IP = "192.168.1.50";

    private static final List<Site> TLS_SITES = List.of(
            new Site("142.250.185.206", "www.google.com", 443),
            new Site("142.250.185.110", "www.youtube.com", 443),
            new Site("157.240.1.35", "www.facebook.com", 443),
            new Site("157.240.1.174", "www.instagram.com", 443),
            new Site("104.244.42.65", "twitter.com", 443),
            new Site("52.94.236.248", "www.amazon.com", 443),
            new Site("23.52.167.61", "www.netflix.com", 443),
            new Site("140.82.114.4", "github.com", 443),
            new Site("104.16.85.20", "discord.com", 443),
            new Site("35.186.224.25", "zoom.us", 443),
            new Site("35.186.227.140", "web.telegram.org", 443),
            new Site("99.86.0.100", "www.tiktok.com", 443),
            new Site("35.186.224.47", "open.spotify.com", 443),
            new Site("192.0.78.24", "www.cloudflare.com", 443),
            new Site("13.107.42.14", "www.microsoft.com", 443),
            new Site("17.253.144.10", "www.apple.com", 443));

    private static final List<Site> HTTP_SITES = List.of(
            new Site("93.184.216.34", "example.com", 80),
            new Site("185.199.108.153", "httpbin.org", 80));

    private static final List<String> DNS_QUERIES = List.of(
            "www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com");

    private GenerateTestPcap() {}

    public static void main(String[] args) throws IOException {
        Path out = Path.of(args.length > 0 ? args[0] : "sample/generated_test.pcap");
        generate(out);
        System.out.println("Created " + out + " with test traffic");
        System.out.println("  - " + TLS_SITES.size() + " TLS connections with SNI");
        System.out.println("  - " + HTTP_SITES.size() + " HTTP connections");
        System.out.println("  - " + DNS_QUERIES.size() + " DNS queries");
        System.out.println("  - 5 packets from blocked IP " + BLOCKED_SOURCE_IP);
    }

    /** Writes the sample capture (77 packets) to {@code file}. */
    public static void generate(Path file) throws IOException {
        Random rnd = new Random(42);
        PcapGlobalHeader header = new PcapGlobalHeader(2, 4, 0, 0, 65535, 1, false);
        long[] timestamp = {1_700_000_000L};

        try (PcapWriter w = PcapWriter.create(file, header)) {
            long seq = 1000;

            // HTTPS connections: SYN, SYN-ACK, ACK, then the TLS Client Hello carrying the website name
            for (Site s : TLS_SITES) {
                int srcPort = 49152 + rnd.nextInt(65535 - 49152 + 1);
                byte[] toServer = ethernet(USER_MAC, GATEWAY_MAC, ETHERTYPE_IPV4);
                byte[] toClient = ethernet(GATEWAY_MAC, USER_MAC, ETHERTYPE_IPV4);

                byte[] tcp = tcp(srcPort, s.port(), seq, 0, TCP_SYN);
                emit(w, rnd, timestamp, concat(toServer, ipv4(USER_IP, s.ip(), PROTO_TCP, tcp.length, rnd), tcp));

                tcp = tcp(s.port(), srcPort, seq + 1000, seq + 1, TCP_SYN | TCP_ACK);
                emit(w, rnd, timestamp, concat(toClient, ipv4(s.ip(), USER_IP, PROTO_TCP, tcp.length, rnd), tcp));

                tcp = tcp(srcPort, s.port(), seq + 1, seq + 1001, TCP_ACK);
                emit(w, rnd, timestamp, concat(toServer, ipv4(USER_IP, s.ip(), PROTO_TCP, tcp.length, rnd), tcp));

                byte[] tls = tlsClientHello(s.name(), rnd);
                tcp = tcp(srcPort, s.port(), seq + 1, seq + 1001, TCP_PSH | TCP_ACK);
                emit(w, rnd, timestamp,
                        concat(toServer, ipv4(USER_IP, s.ip(), PROTO_TCP, tcp.length + tls.length, rnd), tcp, tls));
                seq += 10_000;
            }

            // Plain HTTP connections: SYN, then a GET request with a Host header
            for (Site s : HTTP_SITES) {
                int srcPort = 49152 + rnd.nextInt(65535 - 49152 + 1);
                byte[] toServer = ethernet(USER_MAC, GATEWAY_MAC, ETHERTYPE_IPV4);

                byte[] tcp = tcp(srcPort, s.port(), seq, 0, TCP_SYN);
                emit(w, rnd, timestamp, concat(toServer, ipv4(USER_IP, s.ip(), PROTO_TCP, tcp.length, rnd), tcp));

                byte[] http = httpRequest(s.name());
                tcp = tcp(srcPort, s.port(), seq + 1, 1, TCP_PSH | TCP_ACK);
                emit(w, rnd, timestamp,
                        concat(toServer, ipv4(USER_IP, s.ip(), PROTO_TCP, tcp.length + http.length, rnd), tcp, http));
                seq += 10_000;
            }

            // DNS queries over UDP
            for (String domain : DNS_QUERIES) {
                int srcPort = 49152 + rnd.nextInt(65535 - 49152 + 1);
                byte[] dns = dnsQuery(domain, rnd);
                byte[] udp = udp(srcPort, 53, dns.length);
                emit(w, rnd, timestamp, concat(ethernet(USER_MAC, GATEWAY_MAC, ETHERTYPE_IPV4),
                        ipv4(USER_IP, "8.8.8.8", PROTO_UDP, udp.length + dns.length, rnd), udp, dns));
            }

            // Traffic from a source IP that the examples block
            for (int i = 0; i < 5; i++) {
                int srcPort = 49152 + rnd.nextInt(65535 - 49152 + 1);
                byte[] tcp = tcp(srcPort, 443, seq, 0, TCP_SYN);
                emit(w, rnd, timestamp, concat(ethernet("00:11:22:33:44:56", GATEWAY_MAC, ETHERTYPE_IPV4),
                        ipv4(BLOCKED_SOURCE_IP, "172.217.0.100", PROTO_TCP, tcp.length, rnd), tcp));
                seq += 1000;
            }
        }
    }

    /** Writes one packet and advances the fake clock by one second. */
    private static void emit(PcapWriter w, Random rnd, long[] timestamp, byte[] packet) throws IOException {
        w.write(timestamp[0]++, rnd.nextInt(1_000_000), packet);
    }
}

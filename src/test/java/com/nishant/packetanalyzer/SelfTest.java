package com.nishant.packetanalyzer;

import static com.nishant.packetanalyzer.parser.NetConstants.*;
import static com.nishant.packetanalyzer.tools.PacketBuilder.*;

import com.nishant.packetanalyzer.dpi.*;
import com.nishant.packetanalyzer.engine.*;
import com.nishant.packetanalyzer.parser.PacketParser;
import com.nishant.packetanalyzer.parser.ParsedPacket;
import com.nishant.packetanalyzer.pcap.*;
import com.nishant.packetanalyzer.tools.GenerateTestPcap;
import com.nishant.packetanalyzer.util.IpUtils;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.Random;

/**
 * Tiny dependency-free test runner. Run with:  ./run-tests.sh   (or run-tests.bat on Windows)
 * Exits with a non-zero code if any check fails.
 */
public final class SelfTest {
    private static int passed;
    private static int failed;

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS  " + name);
        } else {
            failed++;
            System.out.println("  FAIL  " + name);
        }
    }

    public static void main(String[] args) throws Exception {
        ipUtils();
        parser();
        extractors();
        appClassification();
        rules();
        queue();
        pcapRoundTrip();
        engines();
        System.out.println("\n" + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static byte[] tlsPacket(String sni, String srcIp, String dstIp, int dstPort) {
        Random r = new Random(1);
        byte[] tls = tlsClientHello(sni, r);
        byte[] tcp = tcp(50000, dstPort, 1, 1, TCP_PSH | TCP_ACK);
        return concat(ethernet("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", ETHERTYPE_IPV4),
                ipv4(srcIp, dstIp, PROTO_TCP, tcp.length + tls.length, r), tcp, tls);
    }

    private static void ipUtils() {
        System.out.println("IpUtils");
        check("parse + format round trip", IpUtils.toString(IpUtils.parse("192.168.1.100")).equals("192.168.1.100"));
        check("first octet is the highest byte", IpUtils.parse("1.2.3.4") == 0x01020304);
        boolean threw = false;
        try { IpUtils.parse("300.1.1.1"); } catch (IllegalArgumentException e) { threw = true; }
        check("rejects octet > 255", threw);
        threw = false;
        try { IpUtils.parse("1.2.3"); } catch (IllegalArgumentException e) { threw = true; }
        check("rejects wrong number of octets", threw);
    }

    private static void parser() {
        System.out.println("PacketParser");
        byte[] frame = tlsPacket("www.youtube.com", "192.168.1.100", "142.250.185.110", 443);
        Optional<ParsedPacket> parsed = PacketParser.parse(new RawPacket(1, 2, frame.length, frame));
        check("valid TLS packet parses", parsed.isPresent());
        ParsedPacket p = parsed.get();
        check("source IP", p.srcIpString().equals("192.168.1.100"));
        check("destination IP", p.dstIpString().equals("142.250.185.110"));
        check("ports", p.srcPort == 50000 && p.dstPort == 443);
        check("TCP flags PSH+ACK", PacketParser.tcpFlagsToString(p.tcpFlags).equals("ACK PSH"));
        check("payload starts with TLS handshake byte", frame[p.payloadOffset] == 0x16);
        check("MAC address", p.srcMac.equals("00:11:22:33:44:55"));

        boolean noCrash = true;
        for (int len = 0; len < frame.length; len++) {
            byte[] cut = java.util.Arrays.copyOf(frame, len);
            try { PacketParser.parse(new RawPacket(0, 0, len, cut)); } catch (RuntimeException e) { noCrash = false; }
        }
        check("every truncated prefix is handled without exceptions", noCrash);

        byte[] padded = concat(frame, new byte[10]);  // Ethernet padding after the IP packet
        ParsedPacket pp = PacketParser.parse(new RawPacket(0, 0, padded.length, padded)).get();
        check("Ethernet padding is not counted as payload", pp.payloadLength == p.payloadLength);
    }

    private static void extractors() {
        System.out.println("Extractors (TLS SNI, HTTP Host, DNS)");
        Random r = new Random(7);
        byte[] hello = tlsClientHello("open.spotify.com", r);
        check("SNI extracted", SniExtractor.extract(hello, 0, hello.length).orElse("").equals("open.spotify.com"));
        byte[] http = httpRequest("example.com");
        check("SNI not found in HTTP", SniExtractor.extract(http, 0, http.length).isEmpty());

        boolean noCrash = true;
        for (int len = 0; len < hello.length; len++) {
            try { SniExtractor.extract(hello, 0, len); } catch (RuntimeException e) { noCrash = false; }
        }
        check("truncated Client Hello never throws", noCrash);

        byte[] shifted = concat(new byte[7], hello);  // payload does not start at index 0
        check("works with a non-zero offset", SniExtractor.extract(shifted, 7, hello.length).isPresent());

        check("HTTP Host extracted", HttpHostExtractor.extract(http, 0, http.length).orElse("").equals("example.com"));
        byte[] withPort = "GET / HTTP/1.1\r\nHost: example.org:8080\r\n\r\n".getBytes();
        check("HTTP Host port stripped", HttpHostExtractor.extract(withPort, 0, withPort.length).orElse("").equals("example.org"));
        byte[] fake = "GET / HTTP/1.1\r\nX-Forwarded-Host: evil.com\r\n\r\n".getBytes();
        check("X-Forwarded-Host is not mistaken for Host", HttpHostExtractor.extract(fake, 0, fake.length).isEmpty());

        byte[] dns = dnsQuery("api.twitter.com", r);
        check("DNS query name", DnsExtractor.extractQuery(dns, 0, dns.length).orElse("").equals("api.twitter.com"));
    }

    private static void appClassification() {
        System.out.println("AppType classification");
        check("youtube", AppType.fromHost("www.youtube.com") == AppType.YOUTUBE);
        check("microsoft.com is NOT Twitter (t.co bug in C++ original)", AppType.fromHost("www.microsoft.com") == AppType.MICROSOFT);
        check("netflix.com is NOT Twitter (x.com bug in C++ original)", AppType.fromHost("www.netflix.com") == AppType.NETFLIX);
        check("t.co is Twitter", AppType.fromHost("t.co") == AppType.TWITTER);
        check("api.t.co is Twitter", AppType.fromHost("api.t.co") == AppType.TWITTER);
        check("x.com is Twitter", AppType.fromHost("x.com") == AppType.TWITTER);
        check("case-insensitive", AppType.fromHost("WWW.GitHub.COM") == AppType.GITHUB);
        check("unknown site is HTTPS", AppType.fromHost("example.org") == AppType.HTTPS);
        check("empty is UNKNOWN", AppType.fromHost("") == AppType.UNKNOWN);
        check("app name lookup is case-insensitive", AppType.fromName("youtube").orElse(null) == AppType.YOUTUBE);
        check("twitter alias", AppType.fromName("Twitter").orElse(null) == AppType.TWITTER);
        check("unknown app name", AppType.fromName("Myspace").isEmpty());
    }

    private static void rules() {
        System.out.println("RuleManager");
        PrintStream real = System.out;
        System.setOut(new PrintStream(java.io.OutputStream.nullOutputStream()));
        RuleManager r = new RuleManager();
        r.blockIp("10.0.0.5");
        r.blockApp("TikTok");
        r.blockDomain("facebook");
        r.blockDomain("*.example.com");
        System.setOut(real);
        int other = IpUtils.parse("10.0.0.6");
        check("blocked source IP", r.isBlocked(IpUtils.parse("10.0.0.5"), AppType.HTTPS, ""));
        check("other IP allowed", !r.isBlocked(other, AppType.HTTPS, ""));
        check("blocked app", r.isBlocked(other, AppType.TIKTOK, ""));
        check("domain substring", r.isBlocked(other, AppType.HTTPS, "m.facebook.com"));
        check("wildcard subdomain", r.isBlocked(other, AppType.HTTPS, "a.b.example.com"));
        check("wildcard bare domain", r.isBlocked(other, AppType.HTTPS, "example.com"));
        check("wildcard does not match look-alike", !r.isBlocked(other, AppType.HTTPS, "notexample.com"));
        check("domain match ignores case", r.isBlocked(other, AppType.HTTPS, "WWW.FACEBOOK.COM"));
    }

    private static void queue() throws Exception {
        System.out.println("ThreadSafeQueue");
        ThreadSafeQueue<Integer> q = new ThreadSafeQueue<>(4);
        long[] sum = {0};
        Thread consumer = new Thread(() -> {
            try {
                Integer v;
                while ((v = q.take()) != null) sum[0] += v;
            } catch (InterruptedException ignored) { }
        });
        consumer.start();
        for (int i = 1; i <= 1000; i++) q.put(i);   // far more than the capacity: put() must block and resume
        q.close();
        consumer.join(5000);
        check("consumer received every item before close", sum[0] == 500_500 && !consumer.isAlive());
        check("put after close is rejected", !q.put(1));
    }

    private static void pcapRoundTrip() throws Exception {
        System.out.println("PCAP reader / writer");
        Path f = Files.createTempFile("selftest", ".pcap");
        byte[] a = {1, 2, 3};
        byte[] b = new byte[100];
        try (PcapWriter w = PcapWriter.create(f, new PcapGlobalHeader(2, 4, 0, 0, 65535, 1, false))) {
            w.write(10, 20, a);
            w.write(11, 21, b);
        }
        try (PcapReader r = PcapReader.open(f)) {
            RawPacket p1 = r.next();
            RawPacket p2 = r.next();
            check("first packet round trip", p1.tsSec() == 10 && p1.tsUsec() == 20 && java.util.Arrays.equals(p1.data(), a));
            check("second packet round trip", p2.data().length == 100);
            check("end of file returns null", r.next() == null);
        }
        Files.delete(f);
    }

    private static void engines() throws Exception {
        System.out.println("Engines (end to end on the generated sample, 77 packets)");
        Path in = Files.createTempFile("in", ".pcap");
        Path outS = Files.createTempFile("outS", ".pcap");
        Path outM = Files.createTempFile("outM", ".pcap");
        GenerateTestPcap.generate(in);

        PrintStream real = System.out;
        System.setOut(new PrintStream(java.io.OutputStream.nullOutputStream()));
        RuleManager rs = rules("YouTube", "192.168.1.50", "facebook");
        ProcessingResult single = new SingleThreadEngine(rs).run(in, outS);
        ProcessingResult multi = new MultiThreadEngine(2, 3, rules("YouTube", "192.168.1.50", "facebook")).run(in, outM);
        System.setOut(real);

        check("single: 77 packets analysed", single.packetsAnalyzed == 77);
        check("single: 70 forwarded, 7 dropped", single.forwarded == 70 && single.dropped == 7);
        check("single: 43 flows", single.flows.size() == 43);
        check("multi: same forwarded/dropped as single", multi.forwarded == 70 && multi.dropped == 7);
        check("multi: same flow count as single", multi.flows.size() == 43);
        check("multi: same application counts as single", multi.appCounts.equals(single.appCounts));
        check("multi: every packet went through exactly one fast path",
                java.util.Arrays.stream(multi.fpProcessed).sum() == 77);
        check("output files have the same size", Files.size(outS) == Files.size(outM));
        check("one flow is classified as YouTube", single.appCounts.getOrDefault(AppType.YOUTUBE, 0L) == 1);
        check("Microsoft is classified correctly", single.appCounts.getOrDefault(AppType.MICROSOFT, 0L) == 1);

        Files.delete(in);
        Files.delete(outS);
        Files.delete(outM);
    }

    private static RuleManager rules(String app, String ip, String domain) {
        RuleManager r = new RuleManager();
        r.blockApp(app);
        r.blockIp(ip);
        r.blockDomain(domain);
        return r;
    }
}

package com.nishant.packetanalyzer;

import com.nishant.packetanalyzer.dpi.SniExtractor;
import com.nishant.packetanalyzer.engine.MultiThreadEngine;
import com.nishant.packetanalyzer.engine.ProcessingResult;
import com.nishant.packetanalyzer.engine.Report;
import com.nishant.packetanalyzer.engine.RuleManager;
import com.nishant.packetanalyzer.engine.SingleThreadEngine;
import com.nishant.packetanalyzer.parser.NetConstants;
import com.nishant.packetanalyzer.parser.PacketParser;
import com.nishant.packetanalyzer.parser.ParsedPacket;
import com.nishant.packetanalyzer.pcap.PcapReader;
import com.nishant.packetanalyzer.pcap.RawPacket;
import com.nishant.packetanalyzer.tools.GenerateTestPcap;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

/**
 * Command-line entry point.
 *
 * <pre>
 *   analyze  &lt;pcap&gt; [max]            print every packet layer by layer       (C++ main.cpp)
 *   scan     &lt;pcap&gt;                  one line per packet + website names     (C++ main_simple.cpp)
 *   dpi      &lt;in&gt; &lt;out&gt; [options]   inspect + block, single thread           (C++ main_working.cpp)
 *   dpi-mt   &lt;in&gt; &lt;out&gt; [options]   inspect + block, multi-threaded         (C++ dpi_mt.cpp)
 *   generate [file]                  create a sample capture                 (generate_test_pcap.py)
 * </pre>
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help") || args[0].equals("help")) {
            printUsage();
            System.exit(args.length == 0 ? 1 : 0);
        }
        String command = args[0];
        String[] rest = java.util.Arrays.copyOfRange(args, 1, args.length);
        try {
            int code = switch (command) {
                case "analyze" -> analyze(rest);
                case "scan" -> scan(rest);
                case "dpi" -> dpi(rest, false);
                case "dpi-mt" -> dpi(rest, true);
                case "generate" -> generate(rest);
                default -> {
                    System.err.println("Unknown command: " + command + "\n");
                    printUsage();
                    yield 2;
                }
            };
            System.exit(code);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        } catch (NoSuchFileException e) {
            System.err.println("Error: File not found: " + e.getFile());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Interrupted");
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------ analyze

    private static int analyze(String[] args) throws IOException {
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: analyze <pcap_file> [max_packets]");
        }
        Path file = Path.of(args[0]);
        int maxPackets = args.length >= 2 ? parseInt(args[1], "max_packets") : -1;

        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0");
        System.out.println("====================================\n");

        int count = 0;
        int parseErrors = 0;
        try (PcapReader reader = PcapReader.open(file)) {
            Report.printPcapInfo(System.out, file, reader.header());
            System.out.println("\n--- Reading packets ---");
            RawPacket raw;
            while ((raw = reader.next()) != null) {
                count++;
                Optional<ParsedPacket> parsed = PacketParser.parse(raw);
                if (parsed.isPresent()) {
                    printPacketDetails(parsed.get(), raw, count);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + count);
                    parseErrors++;
                }
                if (maxPackets > 0 && count >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }
        }
        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + count);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");
        return 0;
    }

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private static void printPacketDetails(ParsedPacket p, RawPacket raw, int number) {
        System.out.println("\n========== Packet #" + number + " ==========");
        System.out.printf("Time: %s.%06d%n", TIME_FORMAT.format(Instant.ofEpochSecond(p.tsSec)), p.tsUsec);

        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + p.srcMac);
        System.out.println("  Destination MAC: " + p.dstMac);
        String type = switch (p.etherType) {
            case NetConstants.ETHERTYPE_IPV4 -> " (IPv4)";
            case NetConstants.ETHERTYPE_IPV6 -> " (IPv6)";
            case NetConstants.ETHERTYPE_ARP -> " (ARP)";
            default -> "";
        };
        System.out.printf("  EtherType:       0x%04x%s%n", p.etherType, type);

        if (p.hasIp) {
            System.out.println("\n[IPv" + p.ipVersion + "]");
            System.out.println("  Source IP:      " + p.srcIpString());
            System.out.println("  Destination IP: " + p.dstIpString());
            System.out.println("  Protocol:       " + PacketParser.protocolToString(p.protocol));
            System.out.println("  TTL:            " + p.ttl);
        }
        if (p.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.dstPort);
            System.out.println("  Sequence Number:  " + p.seqNumber);
            System.out.println("  Ack Number:       " + p.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(p.tcpFlags));
        }
        if (p.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + p.srcPort);
            System.out.println("  Destination Port: " + p.dstPort);
        }
        if (p.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + p.payloadLength + " bytes");
            StringBuilder preview = new StringBuilder("  Preview: ");
            int previewLen = Math.min(p.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                preview.append(String.format("%02x ", raw.data()[p.payloadOffset + i]));
            }
            if (p.payloadLength > 32) preview.append("...");
            System.out.println(preview);
        }
    }

    // ------------------------------------------------------------------ scan

    private static int scan(String[] args) throws IOException {
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: scan <pcap_file>");
        }
        int count = 0;
        int tlsCount = 0;
        System.out.println("Processing packets...");
        try (PcapReader reader = PcapReader.open(Path.of(args[0]))) {
            RawPacket raw;
            while ((raw = reader.next()) != null) {
                count++;
                Optional<ParsedPacket> parsed = PacketParser.parse(raw);
                if (parsed.isEmpty() || !parsed.get().hasIp) continue;
                ParsedPacket p = parsed.get();

                StringBuilder line = new StringBuilder("Packet " + count + ": " + p.srcIpString() + ":" + p.srcPort
                        + " -> " + p.dstIpString() + ":" + p.dstPort);
                if (p.hasTcp && p.dstPort == 443 && p.payloadLength > 0) {
                    Optional<String> sni = SniExtractor.extract(raw.data(), p.payloadOffset, p.payloadLength);
                    if (sni.isPresent()) {
                        line.append(" [SNI: ").append(sni.get()).append("]");
                        tlsCount++;
                    }
                }
                System.out.println(line);
            }
        }
        System.out.println("\nTotal packets: " + count);
        System.out.println("SNI extracted: " + tlsCount);
        return 0;
    }

    // ------------------------------------------------------------------ dpi / dpi-mt

    private static int dpi(String[] args, boolean multiThreaded) throws IOException, InterruptedException {
        if (args.length < 2 || args[0].startsWith("--") || args[1].startsWith("--")) {
            printUsage();
            return 1;
        }
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);

        int lbs = 2;
        int fps = 2;
        boolean showFlows = false;
        RuleManager rules = new RuleManager();
        for (int i = 2; i < args.length; i++) {
            String opt = args[i];
            switch (opt) {
                case "--block-ip" -> rules.blockIp(value(args, ++i, opt));
                case "--block-app" -> rules.blockApp(value(args, ++i, opt));
                case "--block-domain" -> rules.blockDomain(value(args, ++i, opt));
                case "--rules" -> rules.loadRules(Path.of(value(args, ++i, opt)));
                case "--show-flows" -> showFlows = true;
                case "--lbs" -> lbs = parseInt(value(args, ++i, opt), opt);
                case "--fps" -> fps = parseInt(value(args, ++i, opt), opt);
                default -> throw new IllegalArgumentException("Unknown option: " + opt);
            }
        }

        ProcessingResult result;
        if (multiThreaded) {
            MultiThreadEngine engine = new MultiThreadEngine(lbs, fps, rules);
            Report.printBanner(System.out, "DPI ENGINE v2.0 (Multi-threaded)",
                    String.format("Load balancers: %d    FPs per LB: %d    Total FPs: %d", lbs, fps, lbs * fps));
            result = engine.run(input, output);
        } else {
            Report.printBanner(System.out, "DPI ENGINE v1.0 (Single-threaded)", null);
            result = new SingleThreadEngine(rules).run(input, output);
        }
        Report.printReport(System.out, result, showFlows);
        System.out.println("\nOutput written to: " + output);
        return 0;
    }

    // ------------------------------------------------------------------ generate

    private static int generate(String[] args) throws IOException {
        GenerateTestPcap.main(args.length > 0 ? new String[] {args[0]} : new String[0]);
        return 0;
    }

    // ------------------------------------------------------------------ helpers

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException("Option " + option + " needs a value");
        }
        return args[index];
    }

    private static int parseInt(String text, String name) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be a number, got '" + text + "'");
        }
    }

    private static void printUsage() {
        System.out.println("""

                Network Packet Analyzer (Java)
                ==============================

                Usage: java -jar packet-analyzer.jar <command> [arguments]

                Commands:
                  analyze <pcap> [max_packets]        Show every packet layer by layer
                  scan <pcap>                         One line per packet, with HTTPS website names
                  dpi     <in.pcap> <out.pcap> [opts] Inspect + filter traffic (single thread)
                  dpi-mt  <in.pcap> <out.pcap> [opts] Inspect + filter traffic (multi-threaded)
                  generate [file.pcap]                Create a sample capture to experiment with

                Options for dpi / dpi-mt:
                  --block-ip <ip>        Drop traffic coming from this source IP
                  --block-app <name>     Drop an application (YouTube, Facebook, TikTok, ...)
                  --block-domain <dom>   Drop a domain: text match ("facebook") or wildcard ("*.tiktok.com")
                  --rules <file>         Load rules from a file (see sample/blocking_rules.txt)
                  --show-flows           Also print the table of tracked connections
                  --lbs <n>              Load balancer threads, dpi-mt only (default 2)
                  --fps <n>              Fast-path threads per load balancer, dpi-mt only (default 2)

                Example:
                  java -jar packet-analyzer.jar dpi-mt sample/test_dpi.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50
                """);
    }
}

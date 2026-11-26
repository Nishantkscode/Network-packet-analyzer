package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.parser.PacketParser;
import com.nishant.packetanalyzer.parser.ParsedPacket;
import com.nishant.packetanalyzer.pcap.PcapReader;
import com.nishant.packetanalyzer.pcap.PcapWriter;
import com.nishant.packetanalyzer.pcap.RawPacket;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;

/**
 * The simple version: one thread reads a packet, inspects it, and writes it out (or drops it).
 * Easiest to understand, and fast enough for small and medium captures
 * (Java port of the C++ main_working.cpp).
 */
public final class SingleThreadEngine {
    private final RuleManager rules;

    public SingleThreadEngine(RuleManager rules) {
        this.rules = rules;
    }

    public ProcessingResult run(Path input, Path output) throws IOException {
        ProcessingResult result = new ProcessingResult();
        PacketProcessor processor = new PacketProcessor(rules);

        try (PcapReader reader = PcapReader.open(input)) {
            Report.printPcapInfo(System.out, input, reader.header());
            try (PcapWriter writer = PcapWriter.create(output, reader.header())) {
                System.out.println("[DPI] Processing packets...");
                long id = 0;
                try {
                    RawPacket raw;
                    while ((raw = reader.next()) != null) {
                        result.packetsRead++;
                        Optional<ParsedPacket> parsed = PacketParser.parse(raw);
                        if (parsed.isEmpty()) continue;
                        PacketJob job = PacketJob.from(id, raw, parsed.get());
                        if (job == null) continue;   // not IPv4 TCP/UDP
                        id++;

                        result.packetsAnalyzed++;
                        result.bytes += raw.data().length;
                        if (parsed.get().hasTcp) result.tcpPackets++; else result.udpPackets++;

                        if (processor.process(job)) {
                            writer.write(job.tsSec(), job.tsUsec(), job.data());
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[DPI] Warning: " + e.getMessage() + " - stopping early");
                }
            }
        }

        result.merge(processor);
        result.blockedApps = rules.blockedApps();
        return result;
    }
}

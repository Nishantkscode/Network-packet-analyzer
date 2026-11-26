package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.dpi.AppType;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The numbers collected while processing one capture file. Used to print the report. */
public final class ProcessingResult {
    public long packetsRead;      // every packet record in the input file
    public long packetsAnalyzed;  // IPv4 TCP/UDP packets that went through the engine
    public long bytes;            // total size of analysed packets
    public long tcpPackets;
    public long udpPackets;
    public long forwarded;
    public long dropped;
    public final Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
    public final List<FlowEntry> flows = new ArrayList<>();
    public Set<AppType> blockedApps = Set.of();

    // Only filled in by the multi-threaded engine
    public long[] lbDispatched;   // packets handled by each load balancer
    public long[] fpProcessed;    // packets handled by each fast path

    public long skipped() {
        return packetsRead - packetsAnalyzed;
    }

    /** Adds one processor's counters (and flows) into this result. */
    void merge(PacketProcessor processor) {
        forwarded += processor.forwarded();
        dropped += processor.dropped();
        processor.appCounts().forEach((app, n) -> appCounts.merge(app, n, Long::sum));
        processor.flows().forEach(flows::add);
    }
}

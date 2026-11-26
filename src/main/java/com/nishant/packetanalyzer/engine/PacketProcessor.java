package com.nishant.packetanalyzer.engine;

import static com.nishant.packetanalyzer.parser.NetConstants.PROTO_TCP;
import static com.nishant.packetanalyzer.parser.NetConstants.PROTO_UDP;

import com.nishant.packetanalyzer.dpi.AppType;
import com.nishant.packetanalyzer.dpi.FiveTuple;
import com.nishant.packetanalyzer.dpi.HttpHostExtractor;
import com.nishant.packetanalyzer.dpi.SniExtractor;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The brain of the program. For every packet it:
 * <ol>
 *   <li>finds (or creates) the flow the packet belongs to   - connection tracking</li>
 *   <li>tries to learn the website name / application       - deep packet inspection</li>
 *   <li>checks the blocking rules                           - filtering</li>
 *   <li>decides: forward or drop</li>
 * </ol>
 *
 * NOT thread-safe on purpose: each worker thread owns its own processor. Because a load balancer always
 * sends the same flow to the same worker, no flow table is ever shared between threads, so no locking is needed.
 */
public final class PacketProcessor {
    private final RuleManager rules;
    private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();
    private final Map<AppType, Long> appCounts = new EnumMap<>(AppType.class);
    private long forwarded;
    private long dropped;

    public PacketProcessor(RuleManager rules) {
        this.rules = rules;
    }

    /** Processes one packet. Returns true to FORWARD it (write to output), false to DROP it. */
    public boolean process(PacketJob pkt) {
        FlowEntry flow = flows.computeIfAbsent(pkt.tuple(), FlowEntry::new);
        flow.packets++;
        flow.bytes += pkt.data().length;

        if (!flow.classified) {
            classify(pkt, flow);
        }

        if (!flow.blocked) {
            Optional<String> reason = rules.blockReason(pkt.tuple().srcIp(), flow.appType, flow.sni);
            if (reason.isPresent()) {
                flow.blocked = true;
                flow.blockReason = reason.get();
                System.out.println("[BLOCKED] " + flow.tuple + " (" + flow.appType.displayName()
                        + (flow.sni.isEmpty() ? "" : ": " + flow.sni) + ") - " + flow.blockReason);
            }
        }

        appCounts.merge(flow.appType, 1L, Long::sum);
        if (flow.blocked) {
            dropped++;
            return false;
        }
        forwarded++;
        return true;
    }

    /** Tries to work out what this flow is, using the payload of the current packet. */
    private void classify(PacketJob pkt, FlowEntry flow) {
        FiveTuple t = pkt.tuple();
        byte[] data = pkt.data();
        int off = pkt.payloadOffset();
        int len = pkt.payloadLength();
        boolean tcp = t.protocol() == PROTO_TCP;

        // HTTPS: the TLS Client Hello contains the website name in plain text.
        if (tcp && t.dstPort() == 443 && len > 5) {
            Optional<String> sni = SniExtractor.extract(data, off, len);
            if (sni.isPresent()) {
                setHost(flow, sni.get());
                return;
            }
        }

        // Plain HTTP: the website name is in the Host header.
        if (tcp && t.dstPort() == 80 && len > 10) {
            Optional<String> host = HttpHostExtractor.extract(data, off, len);
            if (host.isPresent()) {
                setHost(flow, host.get());
                if (flow.appType == AppType.HTTPS) {
                    flow.appType = AppType.HTTP;   // unknown site, but this was plain HTTP, not HTTPS
                }
                return;
            }
        }

        // DNS: recognised by the port number.
        if (t.dstPort() == 53 || t.srcPort() == 53) {
            flow.appType = AppType.DNS;
            flow.classified = true;
            return;
        }

        // Fallback by port. We do NOT mark the flow as classified, because the Client Hello
        // (which reveals the real website) usually arrives a few packets after the TCP handshake.
        if (t.protocol() == PROTO_UDP && t.dstPort() == 443) {
            flow.appType = AppType.QUIC;
        } else if (t.dstPort() == 443) {
            flow.appType = AppType.HTTPS;
        } else if (t.dstPort() == 80) {
            flow.appType = AppType.HTTP;
        }
    }

    private static void setHost(FlowEntry flow, String host) {
        flow.sni = host;
        flow.appType = AppType.fromHost(host);
        flow.classified = true;
    }

    // ---- results, read after the owning thread has finished ----

    public long forwarded() {
        return forwarded;
    }

    public long dropped() {
        return dropped;
    }

    public Map<AppType, Long> appCounts() {
        return appCounts;
    }

    public Iterable<FlowEntry> flows() {
        return flows.values();
    }
}

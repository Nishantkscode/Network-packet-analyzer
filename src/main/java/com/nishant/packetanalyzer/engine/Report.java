package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.dpi.AppType;
import com.nishant.packetanalyzer.pcap.PcapGlobalHeader;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Prints the banner, the file info and the final report. Plain ASCII so it looks right on every console. */
public final class Report {
    private static final int INNER = 68; // characters between the two '|' borders
    private static final int MAX_FLOWS_SHOWN = 50;

    private Report() {}

    // ------------------------------------------------------------------ box drawing

    private static String line(char fill) {
        return "+" + String.valueOf(fill).repeat(INNER) + "+";
    }

    private static void row(PrintStream out, String text) {
        String padded = text.length() > INNER - 2 ? text.substring(0, INNER - 2) : text;
        out.println("| " + String.format("%-" + (INNER - 2) + "s", padded) + " |");
    }

    private static void centered(PrintStream out, String text) {
        int left = Math.max(0, (INNER - text.length()) / 2);
        row(out, " ".repeat(Math.max(0, left - 1)) + text);
    }

    private static void value(PrintStream out, String label, long number) {
        row(out, String.format("%-26s%12d", label, number));
    }

    // ------------------------------------------------------------------ sections

    public static void printBanner(PrintStream out, String title, String detail) {
        out.println();
        out.println(line('='));
        centered(out, title);
        if (detail != null) {
            out.println(line('-'));
            row(out, detail);
        }
        out.println(line('='));
        out.println();
    }

    public static void printPcapInfo(PrintStream out, Path file, PcapGlobalHeader h) {
        out.println("Opened PCAP file: " + file);
        out.println("  Version: " + h.versionMajor() + "." + h.versionMinor());
        out.println("  Snaplen: " + h.snapLen() + " bytes");
        out.println("  Link type: " + h.network() + (h.network() == 1 ? " (Ethernet)" : ""));
    }

    public static void printReport(PrintStream out, ProcessingResult r, boolean showFlows) {
        out.println();
        out.println(line('='));
        centered(out, "PROCESSING REPORT");
        out.println(line('='));
        value(out, "Packets read:", r.packetsRead);
        value(out, "Analyzed (IPv4 TCP/UDP):", r.packetsAnalyzed);
        value(out, "Skipped (other):", r.skipped());
        value(out, "Total bytes:", r.bytes);
        value(out, "TCP packets:", r.tcpPackets);
        value(out, "UDP packets:", r.udpPackets);
        out.println(line('-'));
        value(out, "Forwarded:", r.forwarded);
        value(out, "Dropped:", r.dropped);
        value(out, "Connections (flows):", r.flows.size());

        if (r.lbDispatched != null && r.fpProcessed != null) {
            out.println(line('-'));
            row(out, "THREAD STATISTICS");
            for (int i = 0; i < r.lbDispatched.length; i++) {
                value(out, "  LB" + i + " dispatched:", r.lbDispatched[i]);
            }
            for (int i = 0; i < r.fpProcessed.length; i++) {
                value(out, "  FP" + i + " processed:", r.fpProcessed[i]);
            }
        }

        out.println(line('-'));
        centered(out, "APPLICATION BREAKDOWN");
        out.println(line('-'));
        List<Map.Entry<AppType, Long>> apps = new ArrayList<>(r.appCounts.entrySet());
        apps.sort(Map.Entry.<AppType, Long>comparingByValue().reversed()
                .thenComparing(e -> e.getKey().displayName()));
        for (Map.Entry<AppType, Long> e : apps) {
            double pct = r.packetsAnalyzed > 0 ? 100.0 * e.getValue() / r.packetsAnalyzed : 0;
            String bar = "#".repeat((int) (pct / 5));
            String blocked = r.blockedApps.contains(e.getKey()) ? " (BLOCKED)" : "";
            row(out, String.format("%-14s%7d%6.1f%% %-20s%s", e.getKey().displayName(), e.getValue(), pct, bar, blocked));
        }
        out.println(line('='));

        printDetectedDomains(out, r);
        if (showFlows) {
            printFlows(out, r);
        }
    }

    private static void printDetectedDomains(PrintStream out, ProcessingResult r) {
        Map<String, AppType> domains = new TreeMap<>();
        for (FlowEntry f : r.flows) {
            if (!f.sni.isEmpty()) domains.put(f.sni, f.appType);
        }
        if (domains.isEmpty()) return;
        out.println();
        out.println("[Detected Domains/SNIs]");
        domains.forEach((sni, app) -> out.println("  - " + sni + " -> " + app.displayName()));
    }

    private static void printFlows(PrintStream out, ProcessingResult r) {
        List<FlowEntry> flows = new ArrayList<>(r.flows);
        flows.sort(Comparator.comparingLong((FlowEntry f) -> f.bytes).reversed()
                .thenComparing(f -> f.tuple.toString()));
        out.println();
        out.println("[Tracked Connections] (largest first)");
        out.printf("  %-56s %6s %8s  %s%n", "Connection", "Pkts", "Bytes", "Application");
        int shown = 0;
        for (FlowEntry f : flows) {
            if (shown++ == MAX_FLOWS_SHOWN) {
                out.println("  ... and " + (flows.size() - MAX_FLOWS_SHOWN) + " more");
                break;
            }
            String app = f.appType.displayName() + (f.sni.isEmpty() ? "" : " (" + f.sni + ")")
                    + (f.blocked ? " [BLOCKED]" : "");
            out.printf("  %-56s %6d %8d  %s%n", f.tuple, f.packets, f.bytes, app);
        }
    }
}

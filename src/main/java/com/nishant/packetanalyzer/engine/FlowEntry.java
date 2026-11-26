package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.dpi.AppType;
import com.nishant.packetanalyzer.dpi.FiveTuple;

/** Everything we remember about one connection (flow) while processing a capture. */
public final class FlowEntry {
    public final FiveTuple tuple;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";            // website name once discovered (TLS SNI or HTTP Host)
    public long packets;
    public long bytes;
    public boolean classified;         // true once the website name / protocol is known for sure
    public boolean blocked;            // once true, every packet of this flow is dropped
    public String blockReason = "";

    public FlowEntry(FiveTuple tuple) {
        this.tuple = tuple;
    }
}

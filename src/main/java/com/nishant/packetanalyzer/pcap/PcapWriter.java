package com.nishant.packetanalyzer.pcap;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Writes a .pcap file (always little-endian, microsecond timestamps), openable in Wireshark. */
public final class PcapWriter implements AutoCloseable {
    private final OutputStream out;

    private PcapWriter(OutputStream out) {
        this.out = out;
    }

    /** Creates the file and writes the global header, copying the settings of {@code template}. */
    public static PcapWriter create(Path path, PcapGlobalHeader template) throws IOException {
        OutputStream out = new BufferedOutputStream(Files.newOutputStream(path), 1 << 16);
        try {
            ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(0xa1b2c3d4);
            buf.putShort((short) template.versionMajor());
            buf.putShort((short) template.versionMinor());
            buf.putInt(template.thisZone());
            buf.putInt((int) template.sigFigs());
            buf.putInt((int) template.snapLen());
            buf.putInt((int) template.network());
            out.write(buf.array());
            return new PcapWriter(out);
        } catch (IOException | RuntimeException e) {
            out.close();
            throw e;
        }
    }

    /** Appends one packet. */
    public void write(long tsSec, long tsUsec, byte[] data) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) tsSec);
        buf.putInt((int) tsUsec);
        buf.putInt(data.length);
        buf.putInt(data.length);
        out.write(buf.array());
        out.write(data);
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}

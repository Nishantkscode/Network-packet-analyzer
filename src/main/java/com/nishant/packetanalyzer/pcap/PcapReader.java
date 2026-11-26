package com.nishant.packetanalyzer.pcap;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads packets from a classic .pcap file (the format Wireshark's "Save as ... pcap" produces).
 *
 * File layout:  [global header 24 bytes] then repeated [packet header 16 bytes][packet bytes].
 *
 * Usage:
 * <pre>
 *   try (PcapReader reader = PcapReader.open(path)) {
 *       RawPacket p;
 *       while ((p = reader.next()) != null) { ... }
 *   }
 * </pre>
 */
public final class PcapReader implements AutoCloseable {
    private static final long MAGIC_NATIVE = 0xa1b2c3d4L;   // written by a little-endian machine
    private static final long MAGIC_SWAPPED = 0xd4c3b2a1L;  // written by a big-endian machine
    private static final long MAGIC_PCAPNG = 0x0a0d0d0aL;   // Wireshark's newer default format (not supported)
    private static final int MAX_PACKET_LEN = 65535;

    private final DataInputStream in;
    private final PcapGlobalHeader header;
    private final ByteOrder order;

    private PcapReader(DataInputStream in, PcapGlobalHeader header, ByteOrder order) {
        this.in = in;
        this.header = header;
        this.order = order;
    }

    /** Opens the file and validates its global header. */
    public static PcapReader open(Path path) throws IOException {
        DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path), 1 << 16));
        try {
            byte[] hdr = new byte[24];
            try {
                in.readFully(hdr);
            } catch (EOFException e) {
                throw new IOException("Could not read PCAP global header (file too short): " + path);
            }

            long magic = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
            ByteOrder order;
            if (magic == MAGIC_NATIVE) {
                order = ByteOrder.LITTLE_ENDIAN;
            } else if (magic == MAGIC_SWAPPED) {
                order = ByteOrder.BIG_ENDIAN;
            } else if (magic == MAGIC_PCAPNG) {
                throw new IOException("This is a pcapng file. Re-save it in Wireshark as "
                        + "'Wireshark/tcpdump/... - pcap' (File > Save As) and try again.");
            } else {
                throw new IOException(String.format("Invalid PCAP magic number: 0x%08x", magic));
            }

            ByteBuffer buf = ByteBuffer.wrap(hdr).order(order);
            PcapGlobalHeader header = new PcapGlobalHeader(
                    buf.getShort(4) & 0xFFFF,
                    buf.getShort(6) & 0xFFFF,
                    buf.getInt(8),
                    buf.getInt(12) & 0xFFFFFFFFL,
                    buf.getInt(16) & 0xFFFFFFFFL,
                    buf.getInt(20) & 0xFFFFFFFFL,
                    order == ByteOrder.BIG_ENDIAN);
            return new PcapReader(in, header, order);
        } catch (IOException | RuntimeException e) {
            in.close();
            throw e;
        }
    }

    public PcapGlobalHeader header() {
        return header;
    }

    /**
     * Reads the next packet.
     *
     * @return the packet, or null at the end of the file
     * @throws IOException if the file is corrupt (bad length, truncated packet data)
     */
    public RawPacket next() throws IOException {
        byte[] ph = new byte[16];
        int got = in.readNBytes(ph, 0, ph.length);
        if (got < ph.length) {
            return null; // clean end of file (or a cut-off header, which we treat as the end)
        }
        ByteBuffer buf = ByteBuffer.wrap(ph).order(order);
        long tsSec = buf.getInt(0) & 0xFFFFFFFFL;
        long tsUsec = buf.getInt(4) & 0xFFFFFFFFL;
        long inclLen = buf.getInt(8) & 0xFFFFFFFFL;
        long origLen = buf.getInt(12) & 0xFFFFFFFFL;

        if (inclLen > MAX_PACKET_LEN || (header.snapLen() > 0 && inclLen > header.snapLen())) {
            throw new IOException("Invalid packet length: " + inclLen);
        }
        byte[] data = new byte[(int) inclLen];
        try {
            in.readFully(data);
        } catch (EOFException e) {
            throw new IOException("Could not read packet data (file is truncated)");
        }
        return new RawPacket(tsSec, tsUsec, origLen, data);
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}

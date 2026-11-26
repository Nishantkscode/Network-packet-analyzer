package com.nishant.packetanalyzer.pcap;

/**
 * One captured packet: the 16-byte per-packet header fields plus the raw bytes.
 *
 * @param tsSec   capture time, whole seconds since 1970
 * @param tsUsec  capture time, microseconds part
 * @param origLen length of the packet on the wire (can be larger than data.length if the capture was truncated)
 */
public record RawPacket(long tsSec, long tsUsec, long origLen, byte[] data) {
}

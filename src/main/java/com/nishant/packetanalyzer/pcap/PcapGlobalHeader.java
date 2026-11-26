package com.nishant.packetanalyzer.pcap;

/**
 * The 24-byte header at the very start of every .pcap file.
 *
 * @param byteSwapped true if the file was written in the opposite byte order to the magic number we expect
 * @param network     link-layer type (1 = Ethernet)
 */
public record PcapGlobalHeader(int versionMajor, int versionMinor, int thisZone, long sigFigs,
                               long snapLen, long network, boolean byteSwapped) {
}

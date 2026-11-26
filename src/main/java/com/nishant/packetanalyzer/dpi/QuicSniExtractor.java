package com.nishant.packetanalyzer.dpi;

import static com.nishant.packetanalyzer.util.Bytes.u8;

import java.util.Optional;

/**
 * Very simplified QUIC (HTTP/3) helper, ported from the original project.
 *
 * Real QUIC Initial packets are encrypted with keys derived from public values, so a proper
 * implementation has to decrypt them first. This class only scans for an unencrypted
 * TLS Client Hello pattern, which works on some test captures but is NOT reliable on real traffic.
 */
public final class QuicSniExtractor {
    private QuicSniExtractor() {}

    /** Long-header packets have the top bit of the first byte set. */
    public static boolean isQuicInitial(byte[] data, int off, int len) {
        return len >= 5 && (u8(data, off) & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] data, int off, int len) {
        if (!isQuicInitial(data, off, len)) {
            return Optional.empty();
        }
        for (int i = 5; i + 50 < len; i++) {
            if (u8(data, off + i) == 0x01) { // possible Client Hello handshake type
                Optional<String> sni = SniExtractor.extract(data, off + i - 5, len - i + 5);
                if (sni.isPresent()) {
                    return sni;
                }
            }
        }
        return Optional.empty();
    }
}

package com.nishant.packetanalyzer.dpi;

import static com.nishant.packetanalyzer.util.Bytes.*;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Reads the website name (Server Name Indication, SNI) out of a TLS "Client Hello".
 *
 * Even for HTTPS the very first message of the handshake is NOT encrypted yet, and it contains
 * the domain the browser wants to talk to. That is what makes Deep Packet Inspection possible.
 *
 * <pre>
 * TLS record header (5 bytes)      type 0x16 = handshake | version | length
 * Handshake header  (4 bytes)      type 0x01 = Client Hello | 3-byte length
 * Client Hello body:               version(2) random(32) sessionId cipherSuites compression extensions
 * SNI extension (type 0x0000):     list length(2) | name type(1) = 0 | name length(2) | the hostname
 * </pre>
 *
 * Every method takes (data, offset, length) = "the payload is data[offset .. offset+length)" and
 * checks bounds, so garbage input returns "no SNI" instead of throwing.
 */
public final class SniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {}

    /** True if the payload starts with a complete-looking TLS Client Hello record. */
    public static boolean isClientHello(byte[] data, int off, int len) {
        if (len < 9) return false;                                   // 5 record bytes + 4 handshake bytes
        if (u8(data, off) != CONTENT_TYPE_HANDSHAKE) return false;
        int version = u16(data, off + 1);
        if (version < 0x0300 || version > 0x0304) return false;     // SSL 3.0 .. TLS 1.3
        int recordLength = u16(data, off + 3);
        if (recordLength > len - 5) return false;                    // record must fit in this packet
        return u8(data, off + 5) == HANDSHAKE_CLIENT_HELLO;
    }

    /** Extracts the SNI hostname, or empty if this is not a Client Hello or has no SNI. */
    public static Optional<String> extract(byte[] data, int off, int len) {
        if (!isClientHello(data, off, len)) {
            return Optional.empty();
        }

        int pos = 5 + 4;      // skip record header + handshake header
        pos += 2;             // client version
        pos += 32;            // random

        // Session ID
        if (pos >= len) return Optional.empty();
        pos += 1 + u8(data, off + pos);

        // Cipher suites
        if (pos + 2 > len) return Optional.empty();
        pos += 2 + u16(data, off + pos);

        // Compression methods
        if (pos >= len) return Optional.empty();
        pos += 1 + u8(data, off + pos);

        // Extensions
        if (pos + 2 > len) return Optional.empty();
        int extensionsLength = u16(data, off + pos);
        pos += 2;
        int extensionsEnd = Math.min(pos + extensionsLength, len); // be lenient if truncated

        while (pos + 4 <= extensionsEnd) {
            int type = u16(data, off + pos);
            int extLength = u16(data, off + pos + 2);
            pos += 4;
            if (pos + extLength > extensionsEnd) break;

            if (type == EXTENSION_SNI) {
                if (extLength < 5) break;
                int listLength = u16(data, off + pos);
                if (listLength < 3) break;
                int nameType = u8(data, off + pos + 2);
                int nameLength = u16(data, off + pos + 3);
                if (nameType != SNI_TYPE_HOSTNAME) break;
                if (nameLength > extLength - 5) break;
                return Optional.of(new String(data, off + pos + 5, nameLength, StandardCharsets.ISO_8859_1));
            }
            pos += extLength;
        }
        return Optional.empty();
    }
}

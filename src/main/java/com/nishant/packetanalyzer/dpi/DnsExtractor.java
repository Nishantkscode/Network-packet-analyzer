package com.nishant.packetanalyzer.dpi;

import static com.nishant.packetanalyzer.util.Bytes.*;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Reads the domain name out of a DNS query (the "what is the IP of www.google.com?" question).
 * A DNS name is stored as length-prefixed labels: 3 'www' 6 'google' 3 'com' 0.
 */
public final class DnsExtractor {
    private static final int HEADER_LEN = 12;

    private DnsExtractor() {}

    /** True if this looks like a DNS query (not a response) with at least one question. */
    public static boolean isQuery(byte[] data, int off, int len) {
        if (len < HEADER_LEN) return false;
        if ((u8(data, off + 2) & 0x80) != 0) return false; // QR bit set = it is a response
        return u16(data, off + 4) > 0;                      // QDCOUNT
    }

    public static Optional<String> extractQuery(byte[] data, int off, int len) {
        if (!isQuery(data, off, len)) {
            return Optional.empty();
        }
        StringBuilder domain = new StringBuilder();
        int pos = HEADER_LEN;
        while (pos < len) {
            int labelLength = u8(data, off + pos);
            if (labelLength == 0 || labelLength > 63) break;   // end of name, or compression pointer
            pos++;
            if (pos + labelLength > len) break;
            if (domain.length() > 0) domain.append('.');
            domain.append(new String(data, off + pos, labelLength, StandardCharsets.ISO_8859_1));
            pos += labelLength;
        }
        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}

package com.nishant.packetanalyzer.dpi;

import static com.nishant.packetanalyzer.util.Bytes.u8;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Reads the "Host:" header of a plain (unencrypted) HTTP request, e.g. {@code Host: example.com}. */
public final class HttpHostExtractor {
    // First four letters of the common HTTP methods: GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS
    private static final String[] METHODS = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

    private HttpHostExtractor() {}

    public static boolean isHttpRequest(byte[] data, int off, int len) {
        if (len < 4) return false;
        String start = new String(data, off, 4, StandardCharsets.ISO_8859_1);
        for (String method : METHODS) {
            if (start.equals(method)) return true;
        }
        return false;
    }

    /** Returns the host name without any ":port" part, or empty if there is no Host header. */
    public static Optional<String> extract(byte[] data, int off, int len) {
        if (!isHttpRequest(data, off, len)) {
            return Optional.empty();
        }
        for (int i = 0; i + 6 < len; i++) {
            // The header must start at the beginning of a line (so "X-Forwarded-Host:" is not matched).
            if (i > 0 && u8(data, off + i - 1) != '\n') continue;
            if (!matchesIgnoreCase(data, off + i, "host:")) continue;

            int start = i + 5;
            while (start < len && (data[off + start] == ' ' || data[off + start] == '\t')) start++;
            int end = start;
            while (end < len && data[off + end] != '\r' && data[off + end] != '\n') end++;
            if (end <= start) continue;

            String host = new String(data, off + start, end - start, StandardCharsets.ISO_8859_1).trim();
            if (host.startsWith("[")) {                 // IPv6 literal such as [::1]:8080
                int close = host.indexOf(']');
                return Optional.of(close > 0 ? host.substring(0, close + 1) : host);
            }
            int colon = host.indexOf(':');              // strip the port
            return Optional.of(colon >= 0 ? host.substring(0, colon) : host);
        }
        return Optional.empty();
    }

    private static boolean matchesIgnoreCase(byte[] data, int pos, String text) {
        for (int k = 0; k < text.length(); k++) {
            if (Character.toLowerCase((char) u8(data, pos + k)) != text.charAt(k)) return false;
        }
        return true;
    }
}

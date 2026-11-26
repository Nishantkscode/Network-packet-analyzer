package com.nishant.packetanalyzer.util;

/**
 * Tiny helpers for reading numbers out of a byte[].
 *
 * Network protocols store numbers in "big-endian" order (most significant byte first).
 * Java's byte is signed (-128..127), so every read masks with 0xFF to get 0..255.
 * This replaces the C++ ntohs()/ntohl() + reinterpret_cast tricks.
 */
public final class Bytes {
    private Bytes() {}

    /** Unsigned 8-bit value at index i. */
    public static int u8(byte[] b, int i) {
        return b[i] & 0xFF;
    }

    /** Unsigned 16-bit big-endian value at index i. */
    public static int u16(byte[] b, int i) {
        return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
    }

    /** Unsigned 24-bit big-endian value at index i (used by TLS handshake lengths). */
    public static int u24(byte[] b, int i) {
        return ((b[i] & 0xFF) << 16) | ((b[i + 1] & 0xFF) << 8) | (b[i + 2] & 0xFF);
    }

    /** Unsigned 32-bit big-endian value at index i (returned as long so it never goes negative). */
    public static long u32(byte[] b, int i) {
        return ((long) (b[i] & 0xFF) << 24) | ((b[i + 1] & 0xFF) << 16)
                | ((b[i + 2] & 0xFF) << 8) | (b[i + 3] & 0xFF);
    }

    /** Raw 32-bit big-endian value at index i (used for IPv4 addresses). */
    public static int i32(byte[] b, int i) {
        return (int) u32(b, i);
    }
}

package com.nishant.packetanalyzer.util;

/** Conversion between dotted IPv4 text ("192.168.1.5") and a 32-bit int. */
public final class IpUtils {
    private IpUtils() {}

    /**
     * "192.168.1.5" becomes 0xC0A80105 (first octet in the highest byte, same order as on the wire).
     *
     * @throws IllegalArgumentException if the text is not a valid IPv4 address
     */
    public static int parse(String dotted) {
        String[] parts = dotted.trim().split("\\.", -1);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: '" + dotted + "'");
        }
        int ip = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid IPv4 address: '" + dotted + "'");
            }
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: '" + dotted + "'");
            }
            ip = (ip << 8) | octet;
        }
        return ip;
    }

    /** 0xC0A80105 becomes "192.168.1.5". */
    public static String toString(int ip) {
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}

package com.nishant.packetanalyzer.engine;

import com.nishant.packetanalyzer.dpi.AppType;
import com.nishant.packetanalyzer.util.IpUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The blocking rules: which source IPs, applications and domains must be dropped.
 * Rules are added before processing starts, then read by many worker threads at once,
 * so the collections used here are thread-safe.
 *
 * Domain rules:
 * <ul>
 *   <li>{@code facebook}          matches any website name CONTAINING the text "facebook" (www.facebook.com, m.facebook.com ...)</li>
 *   <li>{@code *.tiktok.com}      matches tiktok.com and every subdomain (www.tiktok.com, api.tiktok.com)</li>
 * </ul>
 */
public final class RuleManager {
    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

    /** Blocks all packets whose SOURCE address is this IP. */
    public void blockIp(String ip) {
        blockedIps.add(IpUtils.parse(ip));
        System.out.println("[Rules] Blocked IP: " + ip.trim());
    }

    /**
     * Blocks an application by name (e.g. "YouTube", case-insensitive).
     *
     * @return false (and prints an error) if the name is not a known application
     */
    public boolean blockApp(String name) {
        Optional<AppType> app = AppType.fromName(name);
        if (app.isEmpty()) {
            System.err.println("[Rules] Unknown app: " + name);
            return false;
        }
        blockedApps.add(app.get());
        System.out.println("[Rules] Blocked app: " + app.get().displayName());
        return true;
    }

    /** Blocks a domain: plain text (substring match) or a wildcard like "*.example.com". */
    public void blockDomain(String domain) {
        String d = domain.trim().toLowerCase(Locale.ROOT);
        if (d.isEmpty()) {
            return;
        }
        blockedDomains.add(d);
        System.out.println("[Rules] Blocked domain: " + domain.trim());
    }

    public Set<AppType> blockedApps() {
        return Set.copyOf(blockedApps);
    }

    /**
     * Decides whether a packet's flow must be blocked.
     *
     * @return a short human-readable reason such as "app YouTube", or empty if the packet is allowed
     */
    public Optional<String> blockReason(int srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) {
            return Optional.of("IP " + IpUtils.toString(srcIp));
        }
        if (blockedApps.contains(app)) {
            return Optional.of("app " + app.displayName());
        }
        if (!sni.isEmpty()) {
            String host = sni.toLowerCase(Locale.ROOT);
            for (String rule : blockedDomains) {
                if (domainMatches(host, rule)) {
                    return Optional.of("domain " + rule);
                }
            }
        }
        return Optional.empty();
    }

    public boolean isBlocked(int srcIp, AppType app, String sni) {
        return blockReason(srcIp, app, sni).isPresent();
    }

    private static boolean domainMatches(String host, String rule) {
        if (rule.startsWith("*.")) {
            String base = rule.substring(2);
            return host.equals(base) || host.endsWith("." + base);
        }
        return host.contains(rule);
    }

    /**
     * Loads rules from a text file with sections:
     * <pre>
     * [BLOCKED_IPS]
     * 192.168.1.50
     * [BLOCKED_APPS]
     * YouTube
     * [BLOCKED_DOMAINS]
     * *.tiktok.com
     * </pre>
     * Empty lines and lines starting with '#' are ignored.
     */
    public void loadRules(Path file) throws IOException {
        String section = "";
        for (String raw : Files.readAllLines(file)) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("[")) {
                section = line.toUpperCase(Locale.ROOT);
                continue;
            }
            switch (section) {
                case "[BLOCKED_IPS]" -> blockIp(line);
                case "[BLOCKED_APPS]" -> blockApp(line);
                case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                default -> System.err.println("[Rules] Ignoring line outside a known section: " + line);
            }
        }
        System.out.println("[Rules] Rules loaded from: " + file);
    }
}

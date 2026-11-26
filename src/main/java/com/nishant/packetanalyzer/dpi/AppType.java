package com.nishant.packetanalyzer.dpi;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The kind of traffic / application a flow belongs to.
 * A flow is classified from the website name found inside its packets (see {@link #fromHost}).
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X", "twitter", "x"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;
    private final String[] aliases;

    AppType(String displayName, String... aliases) {
        this.displayName = displayName;
        this.aliases = aliases;
    }

    /** Name shown in reports, e.g. "YouTube". */
    public String displayName() {
        return displayName;
    }

    /** Finds an app by its display name, enum name or alias, ignoring case ("youtube", "Twitter/X", "x"). */
    public static Optional<AppType> fromName(String text) {
        String wanted = text.trim().toLowerCase(Locale.ROOT);
        for (AppType app : values()) {
            if (app.displayName.toLowerCase(Locale.ROOT).equals(wanted)
                    || app.name().toLowerCase(Locale.ROOT).equals(wanted)) {
                return Optional.of(app);
            }
            for (String alias : app.aliases) {
                if (alias.equals(wanted)) {
                    return Optional.of(app);
                }
            }
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // Website name -> application
    // ------------------------------------------------------------------

    /**
     * One matching rule. A host matches if it CONTAINS one of the keywords
     * (e.g. "youtube" matches www.youtube.com) or IS / ENDS WITH one of the exact domains
     * (e.g. "t.co" matches t.co and api.t.co but NOT microsoft.com).
     */
    private record Rule(AppType app, List<String> keywords, List<String> domains) {
        boolean matches(String host) {
            for (String k : keywords) {
                if (host.contains(k)) return true;
            }
            for (String d : domains) {
                if (host.equals(d) || host.endsWith("." + d)) return true;
            }
            return false;
        }
    }

    // Order matters: the first matching rule wins (same order as the original C++ code).
    private static final List<Rule> RULES = List.of(
            new Rule(GOOGLE, List.of("google", "gstatic", "googleapis", "ggpht", "gvt1"), List.of()),
            new Rule(YOUTUBE, List.of("youtube", "ytimg"), List.of("youtu.be")),
            new Rule(FACEBOOK, List.of("facebook", "fbcdn", "fbsbx"), List.of("fb.com", "meta.com")),
            new Rule(INSTAGRAM, List.of("instagram"), List.of()),
            new Rule(WHATSAPP, List.of("whatsapp"), List.of("wa.me")),
            new Rule(TWITTER, List.of("twitter", "twimg"), List.of("x.com", "t.co")),
            new Rule(NETFLIX, List.of("netflix", "nflxvideo", "nflximg"), List.of()),
            new Rule(AMAZON, List.of("amazon", "cloudfront", "aws"), List.of()),
            new Rule(MICROSOFT, List.of("microsoft", "office", "azure", "outlook", "bing"),
                    List.of("msn.com", "live.com")),
            new Rule(APPLE, List.of("apple", "icloud", "mzstatic", "itunes"), List.of()),
            new Rule(TELEGRAM, List.of("telegram"), List.of("t.me")),
            new Rule(TIKTOK, List.of("tiktok", "bytedance"), List.of("musical.ly")),
            new Rule(SPOTIFY, List.of("spotify"), List.of("scdn.co")),
            new Rule(ZOOM, List.of("zoom"), List.of()),
            new Rule(DISCORD, List.of("discord"), List.of()),
            new Rule(GITHUB, List.of("github"), List.of()),
            new Rule(CLOUDFLARE, List.of("cloudflare", "cf-"), List.of()));

    /**
     * Maps a website name (from TLS SNI or an HTTP Host header) to an application.
     * Unrecognised but non-empty names are plain HTTPS; an empty name is UNKNOWN.
     */
    public static AppType fromHost(String host) {
        if (host == null || host.isEmpty()) {
            return UNKNOWN;
        }
        String lower = host.toLowerCase(Locale.ROOT);
        for (Rule rule : RULES) {
            if (rule.matches(lower)) {
                return rule.app();
            }
        }
        return HTTPS;
    }
}

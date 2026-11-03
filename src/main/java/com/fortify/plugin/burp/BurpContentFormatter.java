package com.fortify.plugin.burp;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Turns raw Burp data into values that are safe to store in Fortify SSC custom attributes.
 *
 * <p>SSC renders custom attributes as HTML. Burp's own descriptive fields (issue detail, background,
 * references, classifications) are Burp-generated HTML and are passed through as-is, but anything
 * that comes from the scanned application (HTTP messages, DOM source/sink values) is HTML-escaped
 * so it is shown as text and can never inject markup into the SSC UI.</p>
 */
final class BurpContentFormatter {

    /** Marker appended when content had to be cut to fit the SSC attribute limit. */
    static final String TRUNCATED_MARKER = "\n[... truncated to fit the Fortify SSC attribute limit ...]";

    private static final Pattern CWE_PATTERN = Pattern.compile("CWE-(\\d+)");
    private static final DateTimeFormatter EXPORT_TIME_WITH_ZONE =
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss zzz yyyy", Locale.ENGLISH);
    private static final DateTimeFormatter EXPORT_TIME_NO_ZONE =
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH);
    /** Burp writes exportTime like {@code Fri Apr 30 11:45:49 IST 2021} (java.util.Date#toString). */
    private static final Pattern EXPORT_TIME_PARTS =
            Pattern.compile("^(\\w{3} \\w{3} +\\d{1,2} \\d{1,2}:\\d{2}:\\d{2}) (\\S+) (\\d{4})$");

    /**
     * Zone abbreviations that Java resolves wrongly or not at all. "IST" is ambiguous (India, Israel,
     * Ireland); Java's legacy tables pick Israel and java.time picks UTC, so it is mapped to India
     * Standard Time, the most common origin of Burp exports using it.
     */
    private static final java.util.Map<String, String> ZONE_OVERRIDES = java.util.Map.of(
            "IST", "GMT+05:30",
            "PHT", "GMT+08:00");

    private BurpContentFormatter() {
    }

    /** Escapes text for safe display inside HTML. */
    static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#39;");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Decodes an HTTP message honouring Burp's {@code base64} attribute. If content claimed to be
     * Base64 is not valid Base64 it is shown as-is instead of failing the whole upload.
     */
    static String decode(BurpHttpMessage message) {
        if (message == null || message.getContent() == null) {
            return "";
        }
        String content = message.getContent();
        if (!message.isBase64Encoded()) {
            return content;
        }
        try {
            // Strict decoder (after removing line breaks): the MIME decoder silently skips invalid
            // characters and would turn non-Base64 text into garbage instead of failing.
            byte[] bytes = Base64.getDecoder().decode(content.replaceAll("\\s+", ""));
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return content;
        }
    }

    /**
     * Renders all requests (or all responses) of an issue as escaped {@code <pre>} blocks,
     * never exceeding {@code maxLength} characters.
     */
    static String formatHttpMessages(List<BurpRequestResponse> pairs, boolean requests, int maxLength) {
        if (pairs == null || pairs.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int index = 0;
        for (BurpRequestResponse pair : pairs) {
            if (pair == null) {
                continue;
            }
            BurpHttpMessage message = requests ? pair.getRequest() : pair.getResponse();
            String decoded = decode(message);
            if (decoded.isEmpty()) {
                continue;
            }
            index++;
            if (pairs.size() > 1) {
                sb.append("<b>").append(requests ? "Request " : "Response ").append(index).append("</b><br/>\n");
            }
            sb.append("<pre><code>").append(escapeHtml(decoded)).append("</code></pre>\n");
        }
        return truncateHtml(sb.toString(), maxLength);
    }

    /** Renders Burp dynamic-analysis (DOM) data as labelled, escaped sections. */
    static String formatDynamicAnalyses(List<BurpDynamicAnalysis> analyses, int maxLength) {
        if (analyses == null || analyses.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (BurpDynamicAnalysis da : analyses) {
            if (da == null) {
                continue;
            }
            if (!first) {
                sb.append("<hr/>\n");
            }
            first = false;
            appendSection(sb, "Source", da.getSource(), false);
            appendSection(sb, "Source value", da.getSourceValue(), false);
            appendSection(sb, "Sink", da.getSink(), false);
            appendSection(sb, "Sink value", da.getSinkValue(), false);
            appendSection(sb, "Origin", da.getOrigin(), false);
            appendSection(sb, "Proof of concept", da.getPoc(), true);
            appendSection(sb, "Source stack trace", da.getSourceStackTrace(), true);
            appendSection(sb, "Sink stack trace", da.getSinkStackTrace(), true);
        }
        return truncateHtml(sb.toString(), maxLength);
    }

    private static void appendSection(StringBuilder sb, String label, String value, boolean preformatted) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        sb.append("<b>").append(label).append("</b><br/>\n");
        if (preformatted) {
            sb.append("<pre><code>").append(escapeHtml(value.trim())).append("</code></pre>\n");
        } else {
            sb.append(escapeHtml(value.trim())).append("<br/>\n");
        }
    }

    /** Extracts CWE identifiers (e.g. "CWE-79, CWE-116") from Burp's vulnerability classifications. */
    static String extractCwes(String classifications) {
        if (classifications == null) {
            return "";
        }
        Set<String> ids = new LinkedHashSet<>();
        Matcher m = CWE_PATTERN.matcher(classifications);
        while (m.find()) {
            ids.add("CWE-" + m.group(1));
        }
        return String.join(", ", ids);
    }

    /**
     * Parses Burp's {@code exportTime}, which Burp writes with {@code java.util.Date#toString()}
     * (e.g. {@code Fri Apr 30 11:45:49 IST 2021}). Strategy, most to least reliable:
     * <ol>
     *   <li>ambiguous or unknown abbreviations are mapped explicitly ({@link #ZONE_OVERRIDES});</li>
     *   <li>the legacy {@link SimpleDateFormat}: the exact inverse of how Burp wrote the value and,
     *       unlike java.time, correct for BST, AEST, GST and similar names;</li>
     *   <li>java.time with the zone name;</li>
     *   <li>the local date-time interpreted as UTC.</li>
     * </ol>
     * Returns {@code null} if the value is unusable. Independent of the server locale and time zone.
     */
    static Date parseExportTime(String exportTime) {
        if (exportTime == null || exportTime.trim().isEmpty()) {
            return null;
        }
        String value = exportTime.trim().replaceAll("\\s+", " ");
        Matcher parts = EXPORT_TIME_PARTS.matcher(value);
        if (parts.matches() && ZONE_OVERRIDES.containsKey(parts.group(2))) {
            value = parts.group(1) + " " + ZONE_OVERRIDES.get(parts.group(2)) + " " + parts.group(3);
        }
        SimpleDateFormat legacy = new SimpleDateFormat("EEE MMM d HH:mm:ss zzz yyyy", Locale.ENGLISH);
        legacy.setLenient(false);
        try {
            return legacy.parse(value);
        } catch (ParseException e) {
            // fall through to java.time
        }
        try {
            return Date.from(ZonedDateTime.parse(value, EXPORT_TIME_WITH_ZONE).toInstant());
        } catch (DateTimeParseException e) {
            // fall through to UTC interpretation
        }
        if (parts.matches()) {
            try {
                LocalDateTime local = LocalDateTime.parse(parts.group(1) + " " + parts.group(3), EXPORT_TIME_NO_ZONE);
                return Date.from(local.toInstant(ZoneOffset.UTC));
            } catch (DateTimeParseException ignored) {
                return null;
            }
        }
        return null;
    }

    /**
     * Truncates HTML produced by this class to {@code maxLength} characters without leaving a
     * dangling entity, surrogate or unclosed {@code <pre><code>} block.
     */
    static String truncateHtml(String html, int maxLength) {
        if (html.length() <= maxLength) {
            return html;
        }
        String closing = "</code></pre>";
        int budget = maxLength - TRUNCATED_MARKER.length() - closing.length();
        if (budget <= 0) {
            return "";
        }
        String cut = html.substring(0, budget);
        int amp = cut.lastIndexOf('&');
        if (amp > cut.lastIndexOf(';')) {
            cut = cut.substring(0, amp);
        }
        int lt = cut.lastIndexOf('<');
        if (lt > cut.lastIndexOf('>')) {
            cut = cut.substring(0, lt);
        }
        if (!cut.isEmpty() && Character.isHighSurrogate(cut.charAt(cut.length() - 1))) {
            cut = cut.substring(0, cut.length() - 1);
        }
        boolean insidePre = cut.lastIndexOf("<pre><code>") > cut.lastIndexOf(closing);
        return cut + TRUNCATED_MARKER + (insidePre ? closing : "");
    }
}

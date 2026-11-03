package com.fortify.plugin.burp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BurpContentFormatterTest {

    private static BurpHttpMessage message(String content, String base64) {
        BurpHttpMessage m = new BurpHttpMessage();
        m.setContent(content);
        m.setBase64(base64);
        return m;
    }

    private static BurpRequestResponse pair(BurpHttpMessage request, BurpHttpMessage response) {
        BurpRequestResponse rr = new BurpRequestResponse();
        rr.setRequest(request);
        rr.setResponse(response);
        return rr;
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testBase64FlagIsHonoured() {
        assertEquals("GET / HTTP/1.1", BurpContentFormatter.decode(message(b64("GET / HTTP/1.1"), "true")));
        assertEquals("GET / HTTP/1.1", BurpContentFormatter.decode(message("GET / HTTP/1.1", "false")));
        assertEquals("GET / HTTP/1.1", BurpContentFormatter.decode(message("GET / HTTP/1.1", null)));
    }

    @Test
    public void testInvalidBase64DoesNotFailTheUpload() {
        assertEquals("not base64 at all!", BurpContentFormatter.decode(message("not base64 at all!", "true")));
    }

    @Test
    public void testMultiLineBase64IsDecoded() {
        String wrapped = b64("HTTP/1.1 200 OK\r\n\r\nhello").replaceAll("(.{8})", "$1\n");
        assertEquals("HTTP/1.1 200 OK\r\n\r\nhello", BurpContentFormatter.decode(message(wrapped, "true")));
    }

    @Test
    public void testHttpMessagesAreHtmlEscaped() {
        String html = BurpContentFormatter.formatHttpMessages(
                List.of(pair(null, message("<script>alert('x')</script> & \"q\"", "false"))), false, 20000);
        assertTrue(html.startsWith("<pre><code>"));
        assertTrue(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;q&quot;"));
        assertFalse(html.contains("<script>"));
    }

    @Test
    public void testMultiplePairsAreNumbered() {
        String html = BurpContentFormatter.formatHttpMessages(List.of(
                pair(message("GET /a", "false"), null),
                pair(message("GET /b", "false"), null)), true, 20000);
        assertTrue(html.contains("<b>Request 1</b>") && html.contains("<b>Request 2</b>"));
        assertTrue(html.indexOf("GET /a") < html.indexOf("GET /b"));
    }

    @Test
    public void testEmptyAndMissingMessages() {
        assertEquals("", BurpContentFormatter.formatHttpMessages(null, true, 20000));
        assertEquals("", BurpContentFormatter.formatHttpMessages(List.of(pair(null, null)), true, 20000));
        assertEquals("", BurpContentFormatter.formatHttpMessages(List.of(pair(message("", "true"), null)), true, 20000));
    }

    @Test
    public void testHugeResponseIsTruncatedSafely() {
        // 30k of characters that all expand when escaped, to stress entity-safe truncation.
        String body = "<&>".repeat(10_000);
        String html = BurpContentFormatter.formatHttpMessages(
                List.of(pair(null, message(b64(body), "true"))), false, 20000);
        assertTrue(html.length() <= 20000, "length " + html.length());
        assertTrue(html.endsWith(BurpContentFormatter.TRUNCATED_MARKER + "</code></pre>"));
        String beforeMarker = html.substring(0, html.indexOf(BurpContentFormatter.TRUNCATED_MARKER));
        assertTrue(beforeMarker.lastIndexOf(';') > beforeMarker.lastIndexOf('&'), "no dangling entity");
    }

    @Test
    public void testDynamicAnalysisIsEscapedAndLabelled() {
        BurpDynamicAnalysis da = new BurpDynamicAnalysis();
        da.setSource("location.hash");
        da.setSink("element.innerHTML");
        da.setSinkValue("<img src=x onerror=alert(1)>");
        String html = BurpContentFormatter.formatDynamicAnalyses(List.of(da), 20000);
        assertTrue(html.contains("<b>Source</b><br/>\nlocation.hash"));
        assertTrue(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assertFalse(html.contains("<img"));
        assertEquals("", BurpContentFormatter.formatDynamicAnalyses(null, 20000));
    }

    @Test
    public void testCweExtraction() {
        String classifications = "<ul><li><a href=\"https://cwe.mitre.org/data/definitions/79.html\">CWE-79: XSS</a></li>"
                + "<li><a href=\"https://cwe.mitre.org/data/definitions/116.html\">CWE-116: Encoding</a></li>"
                + "<li>CWE-79 again</li></ul>";
        assertEquals("CWE-79, CWE-116", BurpContentFormatter.extractCwes(classifications));
        assertEquals("", BurpContentFormatter.extractCwes(null));
        assertEquals("", BurpContentFormatter.extractCwes("<ul><li>CAPEC-63</li></ul>"));
    }

    @Test
    public void testExportTimeParsing() {
        assertEquals(Instant.parse("2023-10-23T12:00:00Z"),
                BurpContentFormatter.parseExportTime("Mon Oct 23 12:00:00 UTC 2023").toInstant());
        // Real-world formats seen in Burp exports, including zones Java cannot always resolve.
        for (String value : new String[] {"Sat Sep 13 22:39:44 CEST 2014", "Fri Apr 30 11:45:49 IST 2021",
                "Wed Jan 27 22:43:35 WIB 2021", "Wed Jan  7 10:15:30 UTC 2026"}) {
            Date d = BurpContentFormatter.parseExportTime(value);
            assertNotNull(d, value);
            String year = value.substring(value.length() - 4);
            assertTrue(d.toInstant().toString().startsWith(year), value + " -> " + d.toInstant());
        }
        // Exact conversions for unambiguous zones and numeric offsets.
        assertEquals(Instant.parse("2014-09-13T20:39:44Z"),
                BurpContentFormatter.parseExportTime("Sat Sep 13 22:39:44 CEST 2014").toInstant());
        assertEquals(Instant.parse("2021-01-27T15:43:35Z"),
                BurpContentFormatter.parseExportTime("Wed Jan 27 22:43:35 WIB 2021").toInstant());
        assertEquals(Instant.parse("2026-03-10T03:30:00Z"),
                BurpContentFormatter.parseExportTime("Tue Mar 10 09:00:00 GMT+05:30 2026").toInstant());
        assertEquals(Instant.parse("2026-03-10T16:00:00Z"),
                BurpContentFormatter.parseExportTime("Tue Mar 10 09:00:00 PDT 2026").toInstant());
        // Zones java.time gets wrong (BST, AEST, GST) and ambiguous IST (read as India Standard Time).
        assertEquals(Instant.parse("2026-07-15T11:00:00Z"),
                BurpContentFormatter.parseExportTime("Wed Jul 15 12:00:00 BST 2026").toInstant());
        assertEquals(Instant.parse("2026-01-15T02:00:00Z"),
                BurpContentFormatter.parseExportTime("Thu Jan 15 12:00:00 AEST 2026").toInstant());
        assertEquals(Instant.parse("2026-01-15T08:00:00Z"),
                BurpContentFormatter.parseExportTime("Thu Jan 15 12:00:00 GST 2026").toInstant());
        assertEquals(Instant.parse("2021-04-30T06:15:49Z"),
                BurpContentFormatter.parseExportTime("Fri Apr 30 11:45:49 IST 2021").toInstant());
        assertEquals(Instant.parse("2026-01-15T04:00:00Z"),
                BurpContentFormatter.parseExportTime("Thu Jan 15 12:00:00 PHT 2026").toInstant());
        // Unknown zone token: local time interpreted as UTC rather than dropping the date.
        assertEquals(Instant.parse("2026-03-10T09:00:00Z"),
                BurpContentFormatter.parseExportTime("Tue Mar 10 09:00:00 XYZT 2026").toInstant());
        assertNull(BurpContentFormatter.parseExportTime(null));
        assertNull(BurpContentFormatter.parseExportTime(""));
        assertNull(BurpContentFormatter.parseExportTime("not a date"));
    }

    @Test
    public void testExportTimeParsingIsLocaleIndependent() {
        java.util.Locale original = java.util.Locale.getDefault();
        try {
            java.util.Locale.setDefault(java.util.Locale.GERMANY);
            java.util.TimeZone originalZone = java.util.TimeZone.getDefault();
            try {
                java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("America/New_York"));
                assertEquals(Instant.parse("2023-10-23T12:00:00Z"),
                        BurpContentFormatter.parseExportTime("Mon Oct 23 12:00:00 UTC 2023").toInstant());
                assertEquals(Instant.parse("2014-09-13T20:39:44Z"),
                        BurpContentFormatter.parseExportTime("Sat Sep 13 22:39:44 CEST 2014").toInstant());
            } finally {
                java.util.TimeZone.setDefault(originalZone);
            }
        } finally {
            java.util.Locale.setDefault(original);
        }
    }
}

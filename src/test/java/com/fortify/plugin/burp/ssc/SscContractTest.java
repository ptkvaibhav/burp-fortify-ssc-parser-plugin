package com.fortify.plugin.burp.ssc;

import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.burp.BurpParserPlugin;
import com.fortify.plugin.spi.VulnerabilityAttribute;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests that run the plugin through {@link SscSimulator}, which enforces the
 * contract Fortify SSC applies to parser plugin output.
 */
public class SscContractTest {

    private static byte[] resource(String name) throws Exception {
        try (InputStream is = SscContractTest.class.getResourceAsStream(name)) {
            return is.readAllBytes();
        }
    }

    private static Map<String, byte[]> artifact(String xmlName, byte[] xml) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("scan.info", "engineType=BURP\n".getBytes(StandardCharsets.UTF_8));
        entries.put(xmlName, xml);
        return entries;
    }

    private static SscSimulator.Result run(Map<String, byte[]> entries) throws Exception {
        return SscSimulator.run(new BurpParserPlugin(), entries, "BURP");
    }

    @Test
    public void testCurrentBurpFormatIngestsCleanly() throws Exception {
        SscSimulator.Result r = run(artifact("burp-results.xml", resource("/burp-current-format.xml")));

        assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
        assertEquals("2025.12.4", r.getScan().get("setEngineVersion"));
        assertEquals(java.time.Instant.parse("2026-01-07T10:15:30Z"),
                ((java.util.Date) r.getScan().get("setScanDate")).toInstant(), "scan date comes from exportTime");
        assertEquals(4, r.getVulnerabilities().size());

        Map<String, Object> sqli = r.getVulnerabilities().get(0);
        assertEquals("SQL injection", sqli.get("setCategory"));
        assertEquals("https://app.example.com/login", sqli.get("setFileName"));
        assertEquals(BasicVulnerabilityBuilder.Priority.High, sqli.get("setPriority"));
        assertEquals(3.0f, sqli.get("setConfidence"));
        @SuppressWarnings("unchecked")
        Map<String, String> attrs = (Map<String, String>) sqli.get("customAttributes");
        assertTrue(attrs.get("issueDetail").contains("username"));
        assertTrue(attrs.get("issueBackground").startsWith("<p>SQL injection"));

        assertTrue(attrs.get("request").startsWith("<pre><code>POST /login HTTP/1.1"), attrs.get("request"));
        assertTrue(attrs.get("response").contains("500 Internal Server Error"));
        assertEquals("CWE-89", attrs.get("cwe"));
        assertTrue(attrs.get("references").contains("portswigger.net/web-security/sql-injection"));

        assertEquals(BasicVulnerabilityBuilder.Priority.Low, r.getVulnerabilities().get(2).get("setPriority"));
    }

    @Test
    public void testDomIssueWithPlainTextHttpAndDynamicAnalysis() throws Exception {
        SscSimulator.Result r = run(artifact("burp-results.xml", resource("/burp-current-format.xml")));
        Map<String, Object> dom = r.getVulnerabilities().get(3);
        assertEquals("DOM-based cross-site scripting", dom.get("setCategory"));
        @SuppressWarnings("unchecked")
        Map<String, String> attrs = (Map<String, String>) dom.get("customAttributes");
        assertEquals("CWE-79, CWE-116", attrs.get("cwe"));
        // base64="false" content is used verbatim, and markup from the scanned app is escaped.
        assertTrue(attrs.get("request").contains("GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(attrs.get("response").contains("<script>"));
        assertTrue(attrs.get("response").contains("&lt;script&gt;document.getElementById"));
        assertTrue(attrs.get("dynamicAnalysis").contains("<b>Source</b><br/>\nlocation.hash"));
        assertTrue(attrs.get("dynamicAnalysis").contains("<b>Sink</b><br/>\nelement.innerHTML"));
        assertFalse(attrs.get("dynamicAnalysis").contains("<img"));
        // Issues without the optional elements get empty (not null) attributes.
        @SuppressWarnings("unchecked")
        Map<String, String> hsts = (Map<String, String>) r.getVulnerabilities().get(1).get("customAttributes");
        assertEquals("", hsts.get("request"));
        assertEquals("", hsts.get("dynamicAnalysis"));
        assertEquals("", hsts.get("cwe"));
    }

    @Test
    public void testIssueIdsAreUnchangedFromPreviousReleases() throws Exception {
        // Golden IDs produced by released versions 2.0.0 / 2.0.1. Changing them would make SSC treat
        // every existing issue as removed and re-added after an upgrade.
        SscSimulator.Result r = run(artifact("burp-results.xml", resource("/burp-current-format.xml")));
        assertEquals("85c18ccb23a856ae8d2cbf1a7290a687", r.getVulnerabilities().get(0).get("id"));
        assertEquals("692882ba1132f4ff8712cac913f01eae", r.getVulnerabilities().get(1).get("id"));
        SscSimulator.Result legacy = run(artifact("items.xml", resource("/sample-burp.xml")));
        assertEquals("05ad996fa23d05d4f3ed62cc273cab65", legacy.getVulnerabilities().get(0).get("id"));
    }

    @Test
    public void testLegacySavedItemsFormatIngestsCleanly() throws Exception {
        SscSimulator.Result r = run(artifact("items.xml", resource("/sample-burp.xml")));
        assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
        assertEquals(1, r.getVulnerabilities().size());
    }

    @Test
    public void testIdsAreStableAcrossScans() throws Exception {
        byte[] xml = resource("/burp-current-format.xml");
        List<Map<String, Object>> first = run(artifact("a.xml", xml)).getVulnerabilities();
        List<Map<String, Object>> second = run(artifact("b.xml", xml)).getVulnerabilities();
        for (int i = 0; i < first.size(); i++) {
            assertEquals(first.get(i).get("id"), second.get(i).get("id"));
            assertTrue(String.valueOf(first.get(i).get("id")).matches("[0-9a-f]{32}"));
        }
        assertNotEquals(first.get(0).get("id"), first.get(1).get("id"));
    }

    @Test
    public void testIssueWithSameNameOnDifferentLocationsGetsDistinctIds() throws Exception {
        String xml = "<issues>"
                + "<issue><name>XSS</name><host>https://a.example.com</host><path>/p</path>"
                + "<location>/p [q1 parameter]</location><severity>High</severity></issue>"
                + "<issue><name>XSS</name><host>https://a.example.com</host><path>/p</path>"
                + "<location>/p [q2 parameter]</location><severity>High</severity></issue>"
                + "</issues>";
        SscSimulator.Result r = run(artifact("x.xml", xml.getBytes(StandardCharsets.UTF_8)));
        assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
        assertEquals(2, r.getVulnerabilities().size());
    }

    @Test
    public void testOversizedTextIsTruncatedToPluginApiLimits() throws Exception {
        String huge = "x".repeat(VulnerabilityAttribute.MAX_LONG_STRING_LENGTH + 5000);
        String xml = "<issues><issue><name>" + "N".repeat(400) + "</name>"
                + "<host>https://a.example.com</host><path>/" + "p".repeat(400) + "</path>"
                + "<severity>Medium</severity><confidence>Certain</confidence>"
                + "<issueDetail>" + huge + "</issueDetail>"
                + "<issueBackground>" + huge + "</issueBackground>"
                + "<remediationDetail>" + huge + "</remediationDetail>"
                + "<remediationBackground>" + huge + "</remediationBackground>"
                + "</issue></issues>";
        SscSimulator.Result r = run(artifact("big.xml", xml.getBytes(StandardCharsets.UTF_8)));
        assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
        @SuppressWarnings("unchecked")
        Map<String, String> attrs = (Map<String, String>) r.getVulnerabilities().get(0).get("customAttributes");
        assertEquals(VulnerabilityAttribute.MAX_LONG_STRING_LENGTH, attrs.get("issueDetail").length());
    }

    @Test
    public void testZipArtifactAsUploadedToSsc() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
            zos.putNextEntry(new ZipEntry("scan.info"));
            zos.write("engineType=BURP\n".getBytes(StandardCharsets.UTF_8));
            zos.putNextEntry(new ZipEntry("Burp-Results.XML"));
            zos.write(resource("/burp-current-format.xml"));
        }
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("artifact", ".zip");
        try {
            java.nio.file.Files.write(tmp, bos.toByteArray());
            SscSimulator.Result r = run(SscSimulator.readArtifact(tmp));
            assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
            assertEquals(4, r.getVulnerabilities().size());
        } finally {
            java.nio.file.Files.deleteIfExists(tmp);
        }
    }

    @Test
    public void testBurpSavedItemsHistoryExportIsRejectedWithGuidance() throws Exception {
        com.fortify.plugin.api.ScanParsingException e = org.junit.jupiter.api.Assertions.assertThrows(
                com.fortify.plugin.api.ScanParsingException.class,
                () -> run(artifact("history.xml", resource("/burp-saved-items-history.xml"))));
        assertTrue(e.getMessage().contains("Report selected issues"), e.getMessage());
    }

    @Test
    public void testNonIssueEntriesAreSkippedInMixedFiles() throws Exception {
        String xml = "<items>"
                + "<item><url>https://a.example.com/</url><host>a.example.com</host><method>GET</method>"
                + "<path>/</path><status>200</status></item>"
                + "<item><name>SQL injection</name><host>https://a.example.com</host><path>/q</path>"
                + "<location>/q [id parameter]</location><severity>High</severity></item>"
                + "</items>";
        SscSimulator.Result r = run(artifact("mixed.xml", xml.getBytes(StandardCharsets.UTF_8)));
        assertTrue(r.isOk(), () -> "SSC contract problems: " + r.getProblems());
        assertEquals(1, r.getVulnerabilities().size());
        assertEquals("SQL injection", r.getVulnerabilities().get(0).get("setCategory"));
    }

    @Test
    public void testWrongEngineTypeIsReported() throws Exception {
        Map<String, byte[]> entries = artifact("r.xml", resource("/burp-current-format.xml"));
        entries.put("scan.info", "engineType=BURPSUITE\n".getBytes(StandardCharsets.UTF_8));
        assertFalse(run(entries).isOk());
    }
}

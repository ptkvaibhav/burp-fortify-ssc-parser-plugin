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
        assertEquals(3, r.getVulnerabilities().size());

        Map<String, Object> sqli = r.getVulnerabilities().get(0);
        assertEquals("SQL injection", sqli.get("setCategory"));
        assertEquals("https://app.example.com/login", sqli.get("setFileName"));
        assertEquals(BasicVulnerabilityBuilder.Priority.High, sqli.get("setPriority"));
        assertEquals(3.0f, sqli.get("setConfidence"));
        @SuppressWarnings("unchecked")
        Map<String, String> attrs = (Map<String, String>) sqli.get("customAttributes");
        assertTrue(attrs.get("issueDetail").contains("username"));
        assertTrue(attrs.get("issueBackground").startsWith("<p>SQL injection"));

        assertEquals(BasicVulnerabilityBuilder.Priority.Low, r.getVulnerabilities().get(2).get("setPriority"));
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
            assertEquals(3, r.getVulnerabilities().size());
        } finally {
            java.nio.file.Files.deleteIfExists(tmp);
        }
    }

    @Test
    public void testWrongEngineTypeIsReported() throws Exception {
        Map<String, byte[]> entries = artifact("r.xml", resource("/burp-current-format.xml"));
        entries.put("scan.info", "engineType=BURPSUITE\n".getBytes(StandardCharsets.UTF_8));
        assertFalse(run(entries).isOk());
    }
}

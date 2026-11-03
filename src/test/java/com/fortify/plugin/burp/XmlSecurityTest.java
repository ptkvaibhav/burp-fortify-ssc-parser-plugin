package com.fortify.plugin.burp;

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Regression tests ensuring the XML parser used for untrusted uploads is hardened
 * against XXE and entity-expansion attacks, while still accepting real Burp exports
 * (which ship with an internal DTD subset).
 */
public class XmlSecurityTest {

    private final XmlMapper mapper = BurpParserPlugin.createSecureXmlMapper();

    @Test
    public void testExternalEntityIsNotResolved(@TempDir Path tmp) throws Exception {
        Path secret = tmp.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET", StandardCharsets.UTF_8);
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE issues [<!ENTITY xxe SYSTEM \"" + secret.toUri() + "\">]>"
                + "<issues><issue><name>&xxe;</name></issue></issues>";

        Exception e = assertThrows(Exception.class, () -> mapper.readValue(xml, BurpItems.class));
        assertFalse(String.valueOf(e.getMessage()).contains("TOP-SECRET"),
                "External entity content must never be read");
    }

    @Test
    public void testEntityExpansionIsRejected() {
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE issues ["
                + "<!ENTITY a \"aaaaaaaaaa\">"
                + "<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">"
                + "<!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">"
                + "<!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">"
                + "]>"
                + "<issues><issue><name>&d;</name></issue></issues>";

        assertThrows(Exception.class, () -> mapper.readValue(xml, BurpItems.class));
    }

    @Test
    public void testExternalDtdIsNotFetched() throws Exception {
        // Port 1 on loopback is never listening; if the DTD were fetched this would fail or hang.
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE issues SYSTEM \"http://127.0.0.1:1/evil.dtd\">"
                + "<issues><issue><name>Safe</name></issue></issues>";

        BurpItems items = mapper.readValue(xml, BurpItems.class);
        assertEquals("Safe", items.getItems().get(0).getName());
    }

    @Test
    public void testRealBurpInternalDtdSubsetIsAccepted() throws Exception {
        String xml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE issues ["
                + "<!ELEMENT issues (issue*)>"
                + "<!ATTLIST issues burpVersion CDATA \"\">"
                + "<!ATTLIST issues exportTime CDATA \"\">"
                + "<!ELEMENT issue (serialNumber, type, name, host, path, location, severity, confidence)>"
                + "<!ELEMENT name (#PCDATA)>"
                + "<!ELEMENT host (#PCDATA)>"
                + "<!ATTLIST host ip CDATA \"\">"
                + "]>"
                + "<issues burpVersion=\"2025.1\" exportTime=\"Mon Jan 01 00:00:00 UTC 2025\">"
                + "<issue><serialNumber>1</serialNumber><type>1</type>"
                + "<name><![CDATA[SQL injection]]></name>"
                + "<host ip=\"192.0.2.10\">https://app.example.com</host>"
                + "<path>/login</path><location>/login [user parameter]</location>"
                + "<severity>High</severity><confidence>Firm</confidence></issue>"
                + "</issues>";

        BurpItems items = mapper.readValue(xml, BurpItems.class);
        assertNotNull(items.getItems());
        assertEquals("2025.1", items.getBurpVersion());
        assertEquals("SQL injection", items.getItems().get(0).getName());
        assertEquals("https://app.example.com", items.getItems().get(0).getHost());
    }
}

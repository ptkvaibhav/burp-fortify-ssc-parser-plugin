package com.fortify.plugin.burp.ssc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fortify.plugin.burp.BurpParserPlugin;
import com.fortify.plugin.burp.BurpVulnerabilityAttribute;
import com.fortify.plugin.spi.ParserPlugin;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates the plugin descriptor and resources the same way SSC does at install time, using the
 * official {@code pluginmanifest} XSD shipped inside the Fortify {@code plugin-api} artifact.
 */
public class PluginPackagingTest {

    private static final Set<String> TEMPLATE_IDS = Set.of("SIMPLE", "COLLAPSE", "TITLEBOX", "PRIMARYTAG");
    private static final Set<String> DATA_TYPES = Set.of("string", "date", "float");
    /** Built-in issue detail keys that the view template is allowed to reference. */
    private static final Set<String> BUILT_IN_KEYS = Set.of("brief", "detail", "recommendation", "issueName",
            "fullFileName", "shortFileName", "primaryLocation", "category", "subCategory", "severity",
            "confidence", "likelihood", "impact", "accuracy", "probability", "kingdom");

    private static Document pluginXml() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        try (InputStream is = PluginPackagingTest.class.getResourceAsStream("/plugin.xml")) {
            return f.newDocumentBuilder().parse(is);
        }
    }

    private static String text(Document doc, String tag) {
        return doc.getElementsByTagNameNS("*", tag).item(0).getTextContent().trim();
    }

    @Test
    public void testPluginXmlIsValidAgainstOfficialSchema() throws Exception {
        URL xsd = ParserPlugin.class.getResource("/schema/pluginmanifest-1.0.xsd");
        assertNotNull(xsd, "pluginmanifest-1.0.xsd must be available from the plugin-api artifact");
        SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = sf.newSchema(xsd);
        try (InputStream is = getClass().getResourceAsStream("/plugin.xml")) {
            schema.newValidator().validate(new StreamSource(is));
        }
    }

    @Test
    public void testPluginXmlMatchesImplementation() throws Exception {
        Document doc = pluginXml();
        assertEquals(BurpParserPlugin.class.getName(), doc.getDocumentElement().getAttribute("id"));
        assertEquals("1.0", doc.getDocumentElement().getAttribute("api-version"));
        assertEquals("BURP", text(doc, "engine-type"));

        String buildVersion = System.getProperty("plugin.version");
        if (buildVersion != null) {
            assertEquals(buildVersion, text(doc, "version"), "plugin.xml <version> must match build.gradle version");
        }
        assertTrue(Integer.parseInt(text(doc, "data-version")) >= 1);
    }

    @Test
    public void testReferencedResourcesExist() throws Exception {
        Document doc = pluginXml();
        String template = doc.getElementsByTagNameNS("*", "view-template").item(0)
                .getAttributes().getNamedItem("location").getNodeValue();
        assertNotNull(getClass().getResource(template), "view template missing: " + template);
        var images = doc.getElementsByTagNameNS("*", "image");
        for (int i = 0; i < images.getLength(); i++) {
            String loc = images.item(i).getAttributes().getNamedItem("location").getNodeValue();
            assertNotNull(getClass().getResource(loc), "image missing: " + loc);
        }
    }

    @Test
    public void testServiceRegistration() {
        ServiceLoader<ParserPlugin> loader = ServiceLoader.load(ParserPlugin.class);
        boolean found = loader.stream().anyMatch(p -> p.type() == BurpParserPlugin.class);
        assertTrue(found, "META-INF/services must register " + BurpParserPlugin.class.getName());
    }

    @Test
    public void testViewTemplateFollowsSscRules() throws Exception {
        JsonNode root;
        try (InputStream is = getClass().getResourceAsStream("/viewtemplate/ViewTemplate.json")) {
            root = new ObjectMapper().readTree(new String(is.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertTrue(root.isArray(), "view template must be an array of columns");
        assertTrue(root.size() >= 1 && root.size() <= 3, "SSC supports 1-3 columns");

        Set<String> attributeNames = new HashSet<>();
        for (BurpVulnerabilityAttribute a : BurpVulnerabilityAttribute.values()) {
            attributeNames.add(a.attributeName());
        }
        for (JsonNode column : root) {
            assertTrue(column.isArray() && column.size() > 0, "columns must be non-empty arrays");
            for (JsonNode item : column) {
                checkItem(item, attributeNames);
            }
        }
    }

    private void checkItem(JsonNode item, Set<String> attributeNames) {
        String templateId = item.path("templateId").asText();
        assertTrue(TEMPLATE_IDS.contains(templateId), "unknown templateId " + templateId);
        if (item.has("dataType")) {
            assertTrue(DATA_TYPES.contains(item.get("dataType").asText()), "bad dataType in " + item);
        }
        if (item.has("key")) {
            String key = item.get("key").asText();
            if (key.startsWith("customAttributes.")) {
                String attr = key.substring("customAttributes.".length());
                assertTrue(attributeNames.contains(attr), "view template references undeclared attribute " + attr);
            } else {
                assertTrue(BUILT_IN_KEYS.contains(key), "view template references unknown key " + key);
            }
        }
        if (item.has("items")) {
            for (JsonNode child : item.get("items")) {
                checkItem(child, attributeNames);
            }
        }
    }
}

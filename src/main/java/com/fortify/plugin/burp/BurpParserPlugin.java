package com.fortify.plugin.burp;

import com.ctc.wstx.stax.WstxInputFactory;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.fortify.plugin.spi.VulnerabilityAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.xml.stream.XMLInputFactory;

/**
 * Parses Burp Suite XML reports and ingests vulnerabilities into Fortify SSC.
 * Implements the {@link ParserPlugin} interface to handle the parsing lifecycle.
 * Maps Burp severity, confidence, and custom fields to Fortify's standard model.
 */
public class BurpParserPlugin implements ParserPlugin<BurpVulnerabilityAttribute> {
    private static final Logger LOG = LoggerFactory.getLogger(BurpParserPlugin.class);

    /** Conservative limit for core SSC string fields (category, file name, engine version). */
    static final int MAX_FIELD_LENGTH = 255;
    /** Limit for the vulnerability abstract. */
    static final int MAX_ABSTRACT_LENGTH = 1024;
    /** SSC limit for {@code LONG_STRING} custom attributes, as defined by the plugin API. */
    static final int MAX_LONG_ATTRIBUTE_LENGTH = VulnerabilityAttribute.MAX_LONG_STRING_LENGTH;
    private final XmlMapper xmlMapper = createSecureXmlMapper();

    /**
     * Creates an {@link XmlMapper} backed by a hardened Woodstox StAX factory.
     * DTD processing and external entity resolution are explicitly disabled to prevent
     * XXE (XML External Entity) and entity-expansion ("billion laughs") attacks from
     * untrusted uploaded artifacts. Burp exports include an internal DTD subset that only
     * declares elements and attributes, so these files still parse correctly.
     * Woodstox is instantiated directly (rather than via {@code XMLInputFactory.newFactory()})
     * so that the hardened, bundled implementation is always used regardless of the
     * StAX provider visible on the Fortify SSC thread context classloader.
     *
     * @return a hardened XmlMapper instance
     */
    static XmlMapper createSecureXmlMapper() {
        XMLInputFactory inputFactory = new WstxInputFactory();
        inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        inputFactory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
        return new XmlMapper(XmlFactory.builder().xmlInputFactory(inputFactory).build());
    }

    @Override
    public void start() throws Exception {
        LOG.info("Burp Suite Parser Plugin is starting");
    }

    @Override
    public void stop() throws Exception {
        LOG.info("Burp Suite Parser Plugin is stopping");
    }

    @Override
    public Class<BurpVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return BurpVulnerabilityAttribute.class;
    }

    @Override
    public void parseScan(ScanData scanData, ScanBuilder scanBuilder) throws ScanParsingException, IOException {
        LOG.info("Parsing scan data for session: {}", scanData.getSessionId());
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase(Locale.ROOT).endsWith(".xml"))) {
            if (is == null) {
                LOG.error("No Burp XML file found in the uploaded artifact for session: {}", scanData.getSessionId());
                throw new ScanParsingException("No Burp XML file found in the uploaded artifact.");
            }
            BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
            if (burpItems == null) {
                LOG.error("Failed to parse Burp XML file for session: {}", scanData.getSessionId());
                throw new ScanParsingException("Failed to parse Burp XML file.");
            }
            String version = burpItems.getBurpVersion();
            LOG.info("Detected Burp version: {}", version);
            scanBuilder.setEngineVersion(safeTruncate(version != null ? version : "Unknown", MAX_FIELD_LENGTH));
            scanBuilder.setScanDate(new Date());
            scanBuilder.completeScan();
        } catch (Exception e) {
            LOG.error("Error parsing scan: {}", e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public void parseVulnerabilities(ScanData scanData, VulnerabilityHandler vulnerabilityHandler)
            throws ScanParsingException, IOException {
        LOG.info("Parsing vulnerabilities for session: {}", scanData.getSessionId());
        try (InputStream is = scanData.getInputStream(name -> name.toLowerCase(Locale.ROOT).endsWith(".xml"))) {
            if (is != null) {
                BurpItems burpItems = xmlMapper.readValue(is, BurpItems.class);
                if (burpItems != null && burpItems.getItems() != null) {
                    LOG.info("Found {} issues in Burp XML", burpItems.getItems().size());
                    Set<String> reportedIds = new HashSet<>();
                    for (BurpItem item : burpItems.getItems()) {
                        String uniqueId = generateUniqueId(item);
                        if (reportedIds.add(uniqueId)) {
                            reportIssue(vulnerabilityHandler, item, uniqueId);
                        } else {
                            LOG.debug("Skipping duplicate issue ID in same scan: {}", uniqueId);
                        }
                    }
                } else {
                    LOG.warn("No issues found in Burp XML or failed to parse items");
                }
            } else {
                LOG.error("No Burp XML file found during vulnerability parsing for session: {}", scanData.getSessionId());
            }
        } catch (Exception e) {
            LOG.error("Error parsing vulnerabilities: {}", e.getMessage(), e);
            throw e;
        }
    }

    private void reportIssue(VulnerabilityHandler vulnerabilityHandler, BurpItem item, String uniqueId) {
        StaticVulnerabilityBuilder builder = vulnerabilityHandler.startStaticVulnerability(uniqueId);
        
        String name = item.getName() != null ? item.getName() : "Unknown";
        builder.setCategory(safeTruncate(name, MAX_FIELD_LENGTH));
        
        String host = item.getHost() != null ? item.getHost() : "";
        String path = item.getPath() != null ? item.getPath() : "";
        String fileName = host + path;
        if (fileName.isEmpty()) {
            fileName = "Unknown";
        }
        builder.setFileName(safeTruncate(fileName, MAX_FIELD_LENGTH));
        
        builder.setPriority(mapPriority(item.getSeverity()));
        builder.setConfidence(mapConfidence(item.getConfidence()));
        builder.setImpact(mapImpact(item.getSeverity()));
        
        String detail = item.getIssueDetail() != null ? item.getIssueDetail() : name;
        builder.setVulnerabilityAbstract(safeTruncate(detail, MAX_ABSTRACT_LENGTH));
        
        // Custom attributes - Ensure non-null to avoid SSC rendering issues
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_NAME, safeTruncate(item.getName(), MAX_FIELD_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.SEVERITY, safeTruncate(item.getSeverity(), MAX_FIELD_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.CONFIDENCE, safeTruncate(item.getConfidence(), MAX_FIELD_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.FULL_FILE_NAME, safeTruncate(host + path, MAX_FIELD_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_DETAIL, safeTruncate(item.getIssueDetail(), MAX_LONG_ATTRIBUTE_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.ISSUE_BACKGROUND, safeTruncate(item.getIssueBackground(), MAX_LONG_ATTRIBUTE_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_DETAIL, safeTruncate(item.getRemediationDetail(), MAX_LONG_ATTRIBUTE_LENGTH));
        builder.setStringCustomAttributeValue(BurpVulnerabilityAttribute.REMEDIATION_BACKGROUND,
                safeTruncate(item.getRemediationBackground(), MAX_LONG_ATTRIBUTE_LENGTH));
        
        builder.completeVulnerability();
    }

    private String generateUniqueId(BurpItem item) {
        try {
            // MD5 is used only as a stable, non-security fingerprint for issue correlation in SSC
            // (32 hex chars fits SSC's ID column). Changing the algorithm would change every
            // issue ID and break de-duplication against previously uploaded scans.
            MessageDigest digest = MessageDigest.getInstance("MD5");
            String name = item.getName() != null ? item.getName() : "";
            String host = item.getHost() != null ? item.getHost() : "";
            String path = item.getPath() != null ? item.getPath() : "";
            String location = item.getLocation() != null ? item.getLocation() : "";
            
            String combined = name + "|" + host + "|" + path + "|" + location;
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            LOG.warn("MD5 not available, falling back to serial number for ID");
            return item.getSerialNumber() != null ? item.getSerialNumber() : 
                String.valueOf(System.identityHashCode(item));
        }
    }

    private String safeTruncate(String value, int length) {
        if (value == null) {
            return "";
        }
        if (value.length() <= length) {
            return value;
        }
        int end = length;
        // Avoid splitting a surrogate pair, which would leave an invalid UTF-16 sequence.
        if (Character.isHighSurrogate(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }

    private BasicVulnerabilityBuilder.Priority mapPriority(String severity) {
        if (severity == null) {
            return BasicVulnerabilityBuilder.Priority.Low;
        }
        switch (severity.toLowerCase(Locale.ROOT)) {
            case "critical":
                return BasicVulnerabilityBuilder.Priority.Critical;
            case "high":
                return BasicVulnerabilityBuilder.Priority.High;
            case "medium":
                return BasicVulnerabilityBuilder.Priority.Medium;
            case "low":
            case "information":
            default:
                return BasicVulnerabilityBuilder.Priority.Low;
        }
    }

    private float mapConfidence(String confidence) {
        if (confidence == null) {
            return 1.0f;
        }
        switch (confidence.toLowerCase(Locale.ROOT)) {
            case "certain": return 5.0f;
            case "firm": return 3.0f;
            case "tentative": return 1.0f;
            default: return 1.0f;
        }
    }

    private float mapImpact(String severity) {
        if (severity == null) {
            return 1.0f;
        }
        switch (severity.toLowerCase(Locale.ROOT)) {
            case "critical": return 5.0f;
            case "high": return 4.0f;
            case "medium": return 3.0f;
            case "low": return 2.0f;
            case "information": return 1.0f;
            default: return 1.0f;
        }
    }
}

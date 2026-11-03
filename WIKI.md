# Fortify SSC Burp Suite Parser Plugin Wiki

Welcome to the official Wiki for the **Fortify SSC Burp Suite Parser Plugin**. This wiki provides comprehensive documentation on setup, usage, architecture, and troubleshooting.

## Table of Contents
1. [Home](#home)
2. [Prerequisites & Installation](#prerequisites--installation)
3. [Usage Guide](#usage-guide)
4. [Architecture & Design](#architecture--design)
5. [Troubleshooting](#troubleshooting)

---

## Home
This plugin bridges the gap between PortSwigger's **Burp Suite** and OpenText's **Fortify Software Security Center (SSC)**. It implements the Fortify Plugin SPI to natively ingest, parse, and visualize Burp Suite dynamic analysis exports inside the Fortify SSC dashboard.

### Why use this plugin?
- **Unified Dashboard:** View SAST and DAST results in one place.
- **Deduplication:** Stable, deterministic issue IDs (MD5 fingerprint of Issue Name, Host, Path and Location) prevent duplicate findings across scans.
- **Rich Context:** Preserves Burp's "Issue Detail", "Issue Background", "Remediation Detail" and "Remediation Background" inside SSC custom attributes. (HTTP request/response pairs are not currently imported.)
- **Secure by Default:** The XML parser has DTD processing and external entity resolution disabled, so malicious uploads cannot trigger XXE or entity-expansion attacks.

---

## Prerequisites & Installation

### Requirements
- **Fortify SSC:** Version 19.x or newer (fully compatible with 25.4.0).
- **Burp Suite:** Any edition (Professional/Enterprise) capable of exporting XML.
- **Java:** JDK 17 (for building from source; the Gradle toolchain targets Java 17).

### Downloading the Plugin
Download the latest `burp-fortify-ssc-parser-plugin-X.X.X.jar` from the [GitHub Releases](../../releases) page.

### Installing into Fortify SSC
1. Log in to Fortify SSC as an Administrator.
2. Navigate to **Administration > Plugins > Parsers**.
3. Click **Add** and select the downloaded `.jar` file.
4. Accept the plugin terms if prompted.
5. In the Parsers list, locate the **Burp Suite Parser Plugin** and click **Enable**.

---

## Usage Guide

### 1. Exporting from Burp Suite
* Select the issues you want to export in Burp Suite.
* Right-click and choose **Report selected issues**.
* Choose **XML** format (both `Saved Items` `<items>` and `Burp Reports` `<issues>` formats are supported).
* Ensure you include all relevant data (Requests, Responses, Issue Background, etc.).

### 2. Packaging the Scan Artifact
Fortify requires a metadata file to know which parser to invoke.
1. Create a file named exactly `scan.info`.
2. Add the following text to the file: `engineType=BURP`
3. Zip both the `scan.info` and your Burp XML export (e.g., `burp-results.xml`) into a single archive (e.g., `scan-results.zip`).

### 3. Uploading to Fortify
1. In SSC, navigate to your target **Application Version**.
2. Go to the **Artifacts** tab and click **Upload**.
3. Select your `scan-results.zip` file.
4. Once processed, the dynamic findings will appear in your audit view.

---

## Architecture & Design

### Plugin Framework
The plugin implements the `ParserPlugin<BurpVulnerabilityAttribute>` interface from the Fortify Plugin SDK (`com.fortify.plugin:plugin-api`).

### Data Flow
1. **`parseScan()`**: Validates the ZIP artifact, locates the XML file (case-insensitive `.xml`), and records the Burp version as the engine version. The scan date is set to the upload/processing time.
2. **`parseVulnerabilities()`**: Uses a hardened Jackson `XmlMapper` (Woodstox, DTD/external entities disabled) to parse the `<items>/<item>` or `<issues>/<issue>` elements into `BurpItem` objects.
3. **Mapping**: Translates Burp severity to Fortify priority (`High` -> `High`, `Medium` -> `Medium`, `Low`/`Information` -> `Low`), Burp confidence to Fortify confidence (`Certain` = 5, `Firm` = 3, `Tentative` = 1) and severity to impact. Duplicate issues within the same file are reported once.
4. **Vulnerability Builder**: Constructs the Fortify model, populating standard fields and assigning `BurpVulnerabilityAttribute` custom fields.

### View Template
The custom UI layout is defined in `src/main/resources/viewtemplate/ViewTemplate.json`. It uses `TITLEBOX`, `SIMPLE` and `COLLAPSE` templates (array-of-arrays layout, `customAttributes.` key prefix) to cleanly separate Issue Summaries from Technical Details inside the Fortify audit screen.

---

## Troubleshooting

### Common Errors

**Error:** `No valid analysis result was found. Please verify the validity of the result file.`
**Cause:** The uploaded ZIP file does not contain a file with a `.xml` extension, or the `scan.info` file is missing/incorrect.
**Solution:** Ensure your ZIP file contains exactly one `.xml` file and one `scan.info` file with `engineType=BURP`.

**Error:** `Undeclared general entity` / XML parse error mentioning a DOCTYPE or ENTITY.
**Cause:** The XML declares custom entities. For security, the parser does not process DTD entity definitions.
**Solution:** Use an unmodified Burp XML export; standard Burp exports do not rely on custom entities.

**Error:** `Failed to parse Burp XML file.`
**Cause:** The XML file is malformed, empty, or does not have a recognizable root element (`<items>` or `<issues>`).
**Solution:** Re-export the XML from Burp Suite and verify it opens correctly in a browser or text editor.

**Error:** `Plugin is disabled.`
**Cause:** SSC administrators must explicitly enable third-party plugins after uploading them.
**Solution:** Go to **Administration > Plugins > Parsers** and enable the Burp parser.

### Viewing Logs
If you encounter parsing exceptions, you can review the detailed Fortify SSC logs located typically at `<fortify.home>/<app_context>/logs/ssc.log`. Search for `com.fortify.plugin.burp` to see parser-specific debug information.

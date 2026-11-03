# Fortify SSC Burp Suite Parser Plugin Wiki

Welcome to the Wiki for the **Burp Suite Parser Plugin for Fortify SSC**, an independent community project that is not affiliated with OpenText or PortSwigger. This wiki provides comprehensive documentation on setup, usage, architecture, and troubleshooting.

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
- **Rich Context:** Shows Burp's issue and remediation detail and background, the HTTP request/response evidence, CWE IDs, vulnerability classifications, references and DOM-based dynamic analysis inside SSC.
- **Secure by Default:** The XML parser has DTD processing and external entity resolution disabled, so malicious uploads cannot trigger XXE or entity-expansion attacks.

---

## Prerequisites & Installation

### Requirements
- **Fortify SSC / OpenText Application Security:** 23.2 or newer (SSC runs on JDK 17 from 23.2; the plugin is compiled for Java 17).
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
* Choose **XML** format. Note that Burp's separate **Save items** command (Proxy / HTTP history) produces a list of HTTP messages, not scan findings. The plugin rejects such files with a message explaining this.
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
1. **`parseScan()`**: Validates the ZIP artifact, locates the XML file (case-insensitive `.xml`), records the Burp version as the engine version, and takes the scan date from Burp's `exportTime`. If that can't be parsed, it uses the upload time. Zone abbreviations are resolved independently of the server's locale and time zone. The ambiguous `IST` is read as India Standard Time (UTC+05:30); an export from Israel or Ireland would show a time a few hours off, but the date is right.
2. **`parseVulnerabilities()`**: Uses a hardened Jackson `XmlMapper` (Woodstox, DTD/external entities disabled) to parse the `<issues>/<issue>` elements into `BurpItem` objects. An `<items>/<item>` root is also accepted, but only entries that carry issue data (name, type or severity) are imported, so HTTP-history exports are never turned into issues.
3. **Mapping**: Decodes HTTP messages (honouring the `base64` flag), HTML-escapes content that comes from the scanned application, extracts CWE IDs and truncates every field to the plugin-API limits. Translates Burp severity to Fortify priority (`High` -> `High`, `Medium` -> `Medium`, `Low`/`Information` -> `Low`), Burp confidence to Fortify confidence (`Certain` = 5, `Firm` = 3, `Tentative` = 1) and severity to impact. Duplicate issues within the same file are reported once.
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
**Cause:** The XML file is malformed, empty, or does not have a recognizable root element (`<issues>`).

**Error:** `The uploaded XML contains no Burp scan issues. It looks like a Burp 'Save items' (HTTP history) export...`
**Cause:** The file came from Burp's *Save items* command, which exports HTTP traffic, not findings.
**Solution:** In Burp's dashboard or Issues view, select the issues, then use **Report selected issues** → **XML**.
**Solution:** Re-export the XML from Burp Suite and verify it opens correctly in a browser or text editor.

**Error:** HTTP Request / Response sections are empty.
**Cause:** The Burp export was created without requests and responses, or the issue has no evidence (for example passive or informational issues).
**Solution:** Re-export with requests and responses included. The *Base64-encode* option can be on or off.

**Error:** `Plugin cannot be installed` after downgrading from 2.1.x to 2.0.x.
**Cause:** 2.1.0 raised the plugin `data-version`, and SSC refuses plugins with a lower data version.
**Solution:** Stay on 2.1.x or later.

**Error:** `Plugin is disabled.`
**Cause:** SSC administrators must explicitly enable third-party plugins after uploading them.
**Solution:** Go to **Administration > Plugins > Parsers** and enable the Burp parser.

**Error:** `Plugin cannot be installed` / version conflict.
**Cause:** SSC blocks installing an older version of a plugin while a newer one is installed, and only one version can be enabled at a time.
**Solution:** Disable the old version, then enable the new one. To downgrade, remove the newer version first.

### Testing Without SSC
Run `./gradlew verifyReport -Preport=/path/to/export.xml` to push a real Burp export (or an SSC upload ZIP) through the offline SSC contract simulator. It reports the number of issues per priority and any problem SSC would reject.

### Viewing Logs
If you encounter parsing exceptions, you can review the detailed Fortify SSC logs located typically at `<fortify.home>/<app_context>/logs/ssc.log`. Search for `com.fortify.plugin.burp` to see parser-specific debug information. Plugin-container output is also written to `plugin-framework.log` under `<fortify.plugins.home>/log`.

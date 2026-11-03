# GEMINI.md - Burp Suite Parser for OpenText Application Security

This document outlines the conventions and context for the development of the Burp Suite parser for OpenText Application Security (formerly Fortify SSC).

## Project Overview
The goal is to create a Java-based plugin for Fortify SSC that enables the ingestion and visualization of Burp Suite scan results.

## Technical Stack
- **Language:** Java 17
- **Build System:** Gradle (using `shadowJar` for fat JAR packaging)
- **Framework:** Fortify Plugin SDK (SPI)
- **Data Formats:** Burp Suite XML (`<items>` and `<issues>` roots), Fortify Internal Model

## Development Guidelines
- **ID Stability:** Vulnerability IDs are an MD5 hex fingerprint of Issue Name, Host, Path and Location. Do not change the algorithm or inputs, or every existing issue in SSC will be re-created.
- **Security:** Always parse XML with `BurpParserPlugin.createSecureXmlMapper()` (DTD/external entities disabled). Use `Locale.ROOT` for case conversions.
- **Test Data:** Only sanitized fixtures (`example.com`, `192.0.2.x`); never real scan output.
- **Surgical Changes:** Focus on implementing the SPI interface (`com.fortify.plugin.spi.ParserPlugin`: `parseScan`, `parseVulnerabilities`) cleanly.
- **Documentation:** Use Javadoc for complex parsing logic.
- **Testing:** Every parser feature must be verified with a unit test using a sample Burp export.

## File Structure Conventions
- `src/main/java`: Plugin implementation.
- `src/main/resources`: `viewtemplate/ViewTemplate.json` and other static resources.
- `src/main/resources/META-INF/services`: SPI registration.
- `src/main/resources/plugin.xml`: Plugin manifest (ends up at the JAR root).

## Build and Deploy
- Run `./gradlew build` to test, lint and build the plugin (`build/libs/burp-fortify-ssc-parser-plugin-<version>.jar`; ignore the `-plain.jar`).
- The resulting JAR should be uploaded via the SSC Administration UI.
- Scans must be ZIPed with a `scan.info` file containing `engineType=BURP`.

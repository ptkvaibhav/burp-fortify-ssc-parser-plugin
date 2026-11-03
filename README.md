<div align="center">
  <img src="src/main/resources/images/logo.png" alt="Plugin Logo" width="150"/>
  <h1>Fortify SSC Burp Suite Parser Plugin</h1>
  <p>An enterprise-grade custom parser plugin for Fortify Software Security Center (OpenText Application Security). Enables seamless ingestion, parsing, and visualization of PortSwigger Burp Suite XML scan results directly within the Fortify SSC dashboard.</p>

  <p>
    <a href="https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin/actions/workflows/ci.yml"><img src="https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin/actions/workflows/ci.yml/badge.svg" alt="Build Status" /></a>
    <a href="https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin/actions/workflows/codeql.yml"><img src="https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a>
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" />
    <img src="https://img.shields.io/badge/Java-17-orange" alt="Java" />
    <img src="https://img.shields.io/badge/Fortify_SSC-19.x+-brightgreen" alt="Fortify" />
    <img src="https://img.shields.io/badge/Version-2.0.0-blueviolet" alt="Version" />
  </p>
</div>

---

## 📖 Overview

Fortify SSC relies on external plugins to support third-party security tools. This plugin implements the modern Fortify Plugin SPI (v1.2.2320.0), bridging the gap between Burp Suite's dynamic analysis exports and Fortify's centralized vulnerability management.

### ✨ Key Features
- **Deterministic ID Generation:** Uses MD5 hashing of Issue Name, Host, Path, and Location to ensure vulnerability IDs remain stable across subsequent scans, preventing duplicates.
- **Rich Attribute Mapping:** Custom attributes ensure that Burp-specific data (e.g., Confidence, Issue Background, Remediation Detail) is fully visible in SSC.
- **Custom View Template:** Includes a tailored UI template (`viewtemplate/ViewTemplate.json`) that organizes issue details cleanly within the SSC interface.
- **Flexible Reports Support:** Parses both standard `Saved Items` XML and the newer `Burp Reports` (`<issues>`) XML structures, with full support for CDATA and complex tags.
- **Hardened XML Parsing:** DTD processing and external entity resolution are explicitly disabled, protecting SSC from XXE and entity-expansion ("billion laughs") attacks in uploaded artifacts.
- **Isolated Dependencies:** Utilizes Gradle Shadow to relocate internal libraries (e.g., Jackson), ensuring zero classloader conflicts within the Fortify environment.
- **Enterprise CI/CD:** Fully integrated GitHub Actions workflow for automated testing, CodeQL security scanning, linting (Checkstyle), and build packaging.

---

## 🚀 Getting Started

### Prerequisites
- **Java:** JDK 17
- **Build Tool:** Gradle 9.8.2 via the bundled wrapper (`./gradlew`) — no local Gradle install required
- **Fortify SSC:** Version 19.x or later (fully tested and compatible with modern releases)
- **Burp Suite:** Export capabilities to XML

### Building the Plugin

The project uses the Gradle Shadow plugin to create a "Fat JAR" required by Fortify.

```bash
# Clone the repository
git clone https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin.git
cd burp-fortify-ssc-parser-plugin

# Build, test and package the Fat JAR
./gradlew clean build
```

The resulting deployment artifact will be located at:
`build/libs/burp-fortify-ssc-parser-plugin-2.0.0.jar`

> **Note:** `build/libs/` also contains a `*-plain.jar` (unshaded classes only). Do **not** upload that one to SSC.

---

## ⚙️ Installation & Usage

### 1. Install into Fortify SSC
1. Log in to your Fortify SSC instance with Administrator privileges.
2. Navigate to **Administration > Plugins > Parsers**.
3. Click **Add** and upload the `burp-fortify-ssc-parser-plugin-2.0.0.jar` file.
4. **Important:** After uploading, locate the "Burp Suite Parser Plugin" in the list and click **Enable**.

### 2. Uploading Scan Results
Fortify SSC requires uploaded artifacts to specify their engine type.

1. Export your Burp Suite scan results in **XML format** (e.g., `burp-results.xml`). In Burp, select the issues, right-click, and choose **Report selected issues** → **XML**.
2. Create a plain text file named `scan.info` in the same directory as your XML file.
3. Add the following exact line to `scan.info`:
   ```text
   engineType=BURP
   ```
4. Create a ZIP archive (e.g., `results.zip`) containing both `burp-results.xml` and `scan.info`.
5. Upload `results.zip` to your chosen Application Version in Fortify SSC.

---

## 🛠️ Development & Architecture

- **`BurpParserPlugin.java`**: The main entry point implementing `ParserPlugin<T>`. Handles generic scan mapping, robust truncation, duplicate prevention, and iteration.
- **`BurpItems.java` / `BurpItem.java`**: Jackson XML data models representing the Burp export structure.
- **`BurpVulnerabilityAttribute.java`**: Enum defining custom fields presented in the SSC UI.

### Code Quality
The project enforces strict code quality standards:
- **Linting:** Run `./gradlew checkstyleMain` to ensure code meets format requirements.
- **Testing:** Run `./gradlew test` to execute the JUnit Jupiter 6 and Mockito test suites verifying edge cases, duplicate handling, CDATA parsing, locale independence and XML security (XXE) hardening.
- **Full check:** `./gradlew build` runs compilation, tests, Checkstyle (main and test), JaCoCo coverage and produces the shaded plugin JAR.
- **Dependency scan:** `./gradlew dependencyCheckAnalyze` runs OWASP Dependency-Check (fails on CVSS ≥ 7.0). Supplying an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) via `NVD_API_KEY` is strongly recommended.

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, and suggest features.

Please also adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 🛡️ Security

Security is a priority. For information on supported versions, how to report vulnerabilities, and our internal checks (CodeQL, Dependabot), please refer to our [Security Policy](SECURITY.md).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 💬 Support

If you need help or have questions, please check out our [Support Guide](SUPPORT.md).

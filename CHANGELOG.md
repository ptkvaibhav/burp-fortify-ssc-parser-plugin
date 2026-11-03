# Changelog

All notable changes to this project will be documented in this file.

## [2.0.1] - 2026-11-03
### Security
- Explicitly hardened XML parsing: the Jackson `XmlMapper` is now backed by a dedicated Woodstox factory with DTD support, external entities and validation disabled (defense-in-depth against XXE / entity-expansion, independent of library defaults or the SSC StAX provider).
- Added `XmlSecurityTest` regression tests for XXE, billion-laughs, external DTD fetching, and acceptance of real Burp internal DTD subsets.
- Removed an internal hostname and private IP address from a unit-test fixture (replaced with `example.com` / `192.0.2.10`).
### Fixed
- `LONG_STRING` custom attributes (Issue Detail/Background, Remediation Detail/Background) were truncated at 32,000 characters, but the plugin API limit is 20,000 (`VulnerabilityAttribute.MAX_LONG_STRING_LENGTH`); very long Burp text could make SSC reject the scan.
- SLF4J is no longer bundled into the plugin JAR. SSC provides it (as in the official Fortify sample parser); the bundled copy had no logging provider, so plugin log output was silently discarded.
- Severity, confidence and file-extension matching now use `Locale.ROOT`, fixing mis-mapping on servers with a Turkish default locale.
- String truncation no longer splits UTF-16 surrogate pairs.
- The plain (unshaded) JAR no longer overwrites the shaded plugin JAR at the same path; it now has a `-plain` classifier.
- Plugin manifest vendor now identifies the project maintainer instead of OpenText.
### Changed
- Dependencies: Jackson aligned via `jackson-bom` 2.22.4 (previously mismatched 2.21.2/2.21.3), SLF4J 2.0.20, JUnit Jupiter 6.1.3, Mockito 5.24.0.
- Build: Gradle wrapper 9.8.2, Shadow 9.6.1, OWASP Dependency-Check 13.0.0 (with optional `NVD_API_KEY`), Checkstyle 10.26.1.
- CI: CodeQL job keeps the required `Analyze (java)` check name; `actions/checkout` v7, `actions/setup-java` v6, `actions/upload-artifact` v7, `gradle/actions/setup-gradle` v6, `github/codeql-action` v4; CodeQL now also scans GitHub Actions workflows and builds Java explicitly; redundant CI Gradle invocations removed.
- Dependabot now groups Jackson, test and GitHub Actions updates (supersedes Dependabot PRs #36–#41, #44, #46).
- Documented compatibility: SSC 23.2+ (Java 17 runtime) and Burp XML exports from 1.6 to 2025.x.
### Added
- Offline SSC simulator (`SscSimulator`) and contract tests, plus `./gradlew verifyReport -Preport=...`, which loads the packaged plugin JAR via `META-INF/services` with only SSC-provided libraries on the classpath and checks real Burp exports without access to SSC.
- Release workflow: merging a new `version` to `main` builds, verifies and publishes the GitHub Release (`v<version>` tag, plugin JAR and SHA-256).
- Verified that 2.0.1 produces identical issue IDs, categories and priorities to 2.0.0 on 457 real Burp issues, so upgrading keeps SSC issue history.
- `plugin.xml` validation against the official `pluginmanifest-1.0.xsd`, view-template rule checks, and a `verifyPluginJar` packaging check wired into `./gradlew build`.
- Test fixture modelled on the current Burp XML export format (validated with Burp's internal DTD).
### Removed
- Previously committed real scan data, generated reports/logs, build outputs and a bundled Gradle distribution are scheduled to be purged from the git history (performed by the maintainer after this release).
- Documentation refreshed (README, WIKI, SECURITY, CONTRIBUTING, SUPPORT, GEMINI, templates) to match the current toolchain and behavior.

## [2.0.0] - 2026-04-20
### Added
- Enterprise-grade readiness: added comprehensive JavaDoc documentation across the codebase.
- Improved `README.md` with professional headers, badges, and detailed integration instructions.
- Addressed all outstanding Dependabot alerts by updating `junit-jupiter` to v5.11.4 and verifying component security.
- Updated GitHub Actions CI and CodeQL workflows to use the latest supported versions (`v4` and `v3` respectively) fixing previously failing CI runs.
### Removed
- Cleaned up the repository by removing the redundant and untracked `temp-sample-parser` directory.

## [1.2.6] - 2026-04-20
### Fixed
- Fixed the persistent "Loading issue details" hang in Fortify SSC by completely refactoring `ViewTemplate.json` to follow the standard array-of-arrays format and correctly using the `customAttributes.` prefix.
- Aligned custom attribute mapping keys with the internal SSC model to ensure UI data binding succeeds.

## [1.2.5] - 2026-04-20
### Fixed
- Fixed "Loading issue details" hang in Fortify SSC by ensuring all custom attributes are non-null (returning empty strings instead of null).
- Improved view template compatibility by simplifying the issue details layout to use the `SIMPLE` template ID.
- Corrected a syntax error in the internal `mapImpact` logic.

## [1.2.4] - 2026-04-20
### Fixed
- Fixed `FMDALException` during scan ingestion by adding robust truncation for all string fields and custom attributes.
- Fixed potential SQL execution failures by implementing duplicate issue ID prevention within a single scan session.
- Fixed missing vulnerability metadata by mapping additional standard fields: `vulnerabilityAbstract`, `confidence`, and `impact`.

## [1.2.3] - 2026-04-20
### Fixed
- Fixed classloader conflicts in Fortify SSC by relocating Jackson dependencies to `com.fortify.plugin.burp.shadow.jackson`.
- Improved XML parsing robustness to handle both `<issues>` and `<items>` root elements more reliably using Jackson annotations.
- Added deterministic ID generation safety checks to prevent potential `NullPointerExceptions` during scan ingestion.

### Added
- Added SLF4J logging throughout the parsing process to provide better diagnostics in the Fortify SSC plugin logs.
- Added more comprehensive unit tests for XML unmarshalling and edge cases in host attribute parsing.

## [1.2.2] - 2026-04-07
### Fixed
- Fixed `FMDALException` in Fortify SSC caused by unique ID length and format by switching from Base64-encoded SHA-256 to a 32-character MD5 hex string.
- Fixed `FMDALException` caused by `fileName` exceeding 255 characters by truncating the `fileName` field.

## [1.2.1] - 2026-04-06
### Fixed
- Fixed critical `ScanParsingException` leading to "No valid analysis result was found" in Fortify SSC. The plugin now properly invokes `scanBuilder.completeScan()` to trigger Fortify's internal processing logic.

## [1.2.0] - 2026-04-06
### Fixed
- Fixed `plugin.xml` parsing error in Fortify SSC by conforming strictly to the `pluginmanifest-1.0.xsd` schema and correct XML namespaces.
- Fixed an issue where `.XML` files with uppercase extensions were rejected by using case-insensitive extension matching.
- Added robust error reporting when no valid XML file is found instead of failing silently.

### Added
- Added support for parsing Burp Reports `<issues>/<issue>` structure, in addition to the standard `<items>/<item>` structure.
- Added official Fortify SSC icons and logos for the plugin UI.
- Relocated the ViewTemplate configuration to align with Fortify reference project conventions.

## [1.0.0] - 2026-04-06
### Added
- Initial production-ready release of the Burp Suite parser for OpenText Application Security (Fortify SSC).
- Full support for Burp Suite XML exports.
- Deterministic vulnerability ID generation (SHA-256).
- Custom attribute mapping for detailed Burp issue metadata.
- Automated CI/CD with GitHub Actions.
- Security scanning with CodeQL and Dependabot.

### Changed
- Upgraded to Java 17 for modern runtime compatibility.
- Upgraded build infrastructure to Gradle 9.4.1.
- Migrated to `com.gradleup.shadow` plugin for robust artifact packaging.
- Updated all dependencies to their latest secure versions (Jackson 2.18, JUnit 6.0, Mockito 5.23).

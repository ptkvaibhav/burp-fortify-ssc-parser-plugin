# Contributing to Fortify SSC Burp Suite Parser

First off, thank you for considering contributing to this project! It's people like you that make this tool better for everyone.

## How Can I Contribute?

### Reporting Bugs
This section guides you through submitting a bug report. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

- Use the **Bug Report Template** provided in the repository.
- Explain the problem and include additional details to help maintainers reproduce the problem.

### Suggesting Enhancements
This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

- Use the **Feature Request Template** provided in the repository.
- Provide a clear and descriptive title for the issue.

### Pull Requests
The process described here has several goals:
- Maintain code quality.
- Fix problems that are important to users.
- Engage the community in working toward the best possible solutions.

1. Fork the repository and create your branch from `main`.
2. If you've added code that should be tested, add tests (JUnit Jupiter 6 + Mockito).
3. Ensure the test suite passes (`./gradlew test`).
4. Ensure your code passes linting (`./gradlew checkstyleMain checkstyleTest`), or simply run `./gradlew build`, which runs everything.
5. Update the documentation (README.md, WIKI.md, CHANGELOG.md) if applicable. Optionally run `./gradlew verifyReport -Preport=<your sanitized export>` to check the packaged JAR end to end.
6. **Never commit real scan data.** Test fixtures must use sanitized hosts (e.g. `example.com`, `192.0.2.x`) — no customer or internal hostnames, IPs, or request/response bodies.
7. Submit a pull request using the provided **Pull Request Template**.

## Development Setup
- JDK 17 (the Gradle toolchain targets Java 17)
- Gradle: use the bundled wrapper (`./gradlew`, currently Gradle 9.8.2) — no local install needed
- Your favorite IDE (IntelliJ IDEA, Eclipse, VS Code).
- See `README.md` for build instructions.
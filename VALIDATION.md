# Validated local results

Validated 25 November 2026 (Australia/Sydney).

Upstream commit: `d96ad5c736b543d9f288d509bae39d42aa9076bf`.

All four scenarios met their expected outcomes using separate initially empty
Maven caches.

| Scenario | Observed outcome |
| --- | --- |
| Baseline | Build, dependency versions and payment output passed |
| Pinned Woodstox | Expected Enforcer failure naming Woodstox 6.0.3 and 6.4.0 |
| Conventional | Build, dependency versions and payment output passed |
| Lightwell | BOM, build, versions and payment output passed |

## Measured dependency changes

- `com.fasterxml.jackson.core:jackson-annotations`
  — baseline: 2.10.2; conventional: 2.13.5; Lightwell: 2.10.2.
- `com.fasterxml.jackson.core:jackson-core`
  — baseline: 2.10.2; conventional: 2.13.5; Lightwell: 2.10.2.
- `com.fasterxml.jackson.core:jackson-databind`
  — baseline: 2.10.2; conventional: 2.13.5; Lightwell: 2.10.2.
- `com.fasterxml.jackson.dataformat:jackson-dataformat-xml`
  — baseline: 2.10.2; conventional: 2.13.5; Lightwell: 2.10.2.
- `com.fasterxml.jackson.module:jackson-module-jaxb-annotations`
  — baseline: 2.10.2; conventional: absent; Lightwell: 2.10.2.
- `com.fasterxml.woodstox:woodstox-core`
  — baseline: 6.0.3; conventional: 6.4.0; Lightwell: 6.0.3.rhlw-00001.
- `jakarta.activation:jakarta.activation-api`
  — baseline: 1.2.1; conventional: absent; Lightwell: 1.2.1.
- `jakarta.xml.bind:jakarta.xml.bind-api`
  — baseline: 2.3.2; conventional: absent; Lightwell: 2.3.2.
- `org.codehaus.woodstox:stax2-api`
  — baseline: 4.2; conventional: 4.2.1; Lightwell: 4.2.

The Lightwell dependency tree differs from baseline only in the Woodstox
version. The application source and original policy exceptions were not changed.

## Toolchain and limits

Maven 3.10.2; Maven used Homebrew OpenJDK 27.0.1.1. The POM compiles for Java
11. This run does not validate execution on a Java 11 runtime.

No vulnerability scanner, exploit test, AWS resource or container runtime was
used. Successful sample output is not proof of CVE remediation or comprehensive
compatibility. The public Lightwell repository prefix metadata emitted
missing-checksum warnings; full logs are retained. Recorded artifact hashes
establish byte identity, not independent vendor authenticity.

[Detailed run report](evidence/20261124T220528172606Z/REPORT.md)

[Machine-readable results and commands](evidence/20261124T220528172606Z/results.json)

[Toolchain](evidence/20261124T220528172606Z/toolchain.txt)

# Lightwell AWS demo — local validation package

This first increment reproduces Derek Waters' four Maven scenarios. It creates
no AWS resources and does not require Docker.

## Presenting with the AWS slide deck

Use [DEMO.md](DEMO.md) for the deck-aligned presenter flow, evidence locations,
AWS architecture status and next validation gates. Insert the demonstration
immediately after **Integrating Lightwell Updates**.

The working demo demonstrates targeted dependency replacement and sample
execution. The wider AWS workflow is proposed: CodeBuild, ECR/Inspector and
Fargate come next. CodeArtifact delivery is a separate integration investigation;
Transform and Continuum are later exercises. No AWS service is invoked by the
local runner.

The four strategic wins in the deck are hypotheses for a customer POC, not
measured results of this example. Do not present sample VEX filtering as
Inspector verification, or artifact hashes as SLSA conformance.

## Run

Prerequisites: Python 3, Maven, and a JDK capable of compiling Java 11. Internet
access to Maven Central and Red Hat's public Lightwell demo Maven repositories
is required. Maven and JDK versions are recorded with each run. The local
workflow does not pin them.

From this directory:

```sh
python3 run_scenarios.py --work-dir /absolute/path/to/scratch
```

Use `--scenario baseline`, `pinned-failure`, `conventional`, or `lightwell` for
a focused rerun. Each invocation creates a new timestamped scratch directory,
and every scenario gets its own initially empty Maven cache. No personal Maven
settings or existing cache are used. JAVA_HOME is respected. Ambient Maven/JVM
option variables are removed for the child builds.

Results appear in `evidence/<UTC-run-id>/REPORT.md` and `results.json`, with
full command logs and toolchain information. The runner exits nonzero if any
expected result fails. A failed pin is a PASS only if the log identifies the
expected Woodstox 6.0.3 / 6.4.0 dependency-convergence failure; arbitrary
network/build failures do not count as success.

## Optional development container

With Docker and the VS Code Dev Containers extension installed, open this folder
and select **Dev Containers: Reopen in Container**. The container provides
JDK 11, Maven 3.9.9 and Python 3; its base-image tag and Python packages can
receive updates when rebuilt. It supports both x86-64 and ARM64 hosts.

Run the same command inside the container, for example:

```sh
python3 run_scenarios.py --work-dir /tmp/lightwell-scratch
```

Evidence is written to the workspace as usual. Scratch data under `/tmp` is
container-local and may be lost when the container is removed. Running the
scenarios still requires network access to the Maven repositories.

## Scenarios

| Scenario | Jackson XML | Woodstox | Expected result |
| --- | --- | --- | --- |
| baseline | 2.10.2 | 6.0.3 | Build and smoke check pass |
| pinned-failure | 2.10.2 | 6.4.0 direct pin | Expected convergence failure |
| conventional | 2.13.5 | 6.4.0 | Build and smoke check pass |
| lightwell | 2.10.2 | 6.0.3.rhlw-00001 | BOM + build + smoke check pass |

The successful cases also validate resolved dependency-tree entries and record
downloaded Jackson/Woodstox JAR SHA-256 hashes. Hashes identify the downloaded
bytes; they are not independent authenticity or remediation proof. Output checks
verify transaction PX-1001, amount 129.99 USD and status APPROVED.

## Provenance and important limits

Source: <https://github.com/derekwaters/parasol-payment-gateway>

Pinned commit: `d96ad5c736b543d9f288d509bae39d42aa9076bf`.

`source/` contains the unchanged upstream application, POM variants, local BOM
and sample VEX. `source/README.md` is a formatting-only adaptation.
`source/DEMOSCRIPT.md` is a locally edited, lint-clean adaptation with corrected
manual-run instructions and evidence qualifications. `SOURCE-MANIFEST.json`
records current checksums and original upstream checksums for adapted files
under `local_adaptations`; the pinned commit identifies the upstream baseline,
not an assertion that the adapted script is byte-identical. The upstream README
has stale layout/description details; the actual source is authoritative.
`config/lightwell-settings.xml` is copied from the upstream sample settings. The
runner selects a POM only in scratch copies. It pins the dependency-tree
reporting plugin to 3.8.1 without editing the original build.

All original Maven Enforcer exceptions remain, including stax2-api and the exact
Lightwell patched version. The expected failure is a dependency-policy
violation, not evidence of runtime incompatibility. The payment output is a
smoke check of fixed XML, not a security regression test or comprehensive
compatibility test. Maven's verify phase does not by itself imply that a
meaningful test suite exists.

The sample OpenVEX is retained as demo source material but is not applied by
this runner. No vulnerability scan, vendor advisory authentication, exploit
regression, Inspector backport recognition, AWS execution or Java 11 runtime
compatibility is certified by these checks. Do not describe a successful build
as proof that the CVE is fixed.

## Next increment

After local scenarios pass: package actual runtime dependencies into three
consistent images; verify execution without dependency downloads; then use
ECR/Inspector to establish scan coverage and actual findings. Add CodeBuild,
Fargate and CloudFormation only after that evidence is understood. AWS account
configuration is intentionally deferred. The acceptance gates and the separate
CodeArtifact investigation are described in [DEMO.md](DEMO.md).

## Cleanup

Scratch directories hold downloaded dependencies and build products. After
preserving needed evidence, remove only the timestamped directories created
under your chosen scratch path. Evidence is kept separately in this package. No
external resources or user Maven configuration need restoring.

## License

Original project contributions are available under the [MIT License](LICENSE),
to the extent their contributors have the right to license them. The copied
and adapted upstream material in `source/` and `config/lightwell-settings.xml`
is not covered by this grant; its licensing and distribution permission have
not been confirmed. Evidence may include output derived from that material and
is also excluded from the grant. See
[SOURCE-MANIFEST.json](SOURCE-MANIFEST.json)
for provenance.

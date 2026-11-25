# Lightwell AWS demo — local validation package

This package reproduces Derek Waters' four Maven scenarios locally and includes
an AWS integration for CodeArtifact, CodeBuild, ECR/Inspector and Fargate.
The local runner creates no AWS resources and does not require Docker.
The AWS integration has also passed live runs with Inspector skipped.

## Presenting with the AWS slide deck

Use [DEMO.md](DEMO.md) for the deck-aligned presenter flow, evidence locations,
AWS architecture status and next validation gates. Insert the demonstration
immediately after **Integrating Lightwell Updates**.

The local demo demonstrates targeted dependency replacement and sample
execution. The AWS code now implements explicit CodeArtifact patch publication,
four CodeBuild scenarios, three ECR images, Inspector evidence collection and
two Fargate tasks. Live AWS runs passed with Inspector skipped; scanning
and backport recognition remain unverified.
Transform and Continuum remain future exercises.

Use [the AWS setup guide](aws/README.md) to package, deploy, run and clean up.
See [local integration validation](aws/LOCAL-VALIDATION.md) for checks completed
without an AWS account. Do not describe those checks as an AWS deployment.

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
full command logs and toolchain information. Generated evidence is ignored by
Git. The runner exits nonzero if any
expected result fails. A failed pin is a PASS only if the log identifies the
expected Woodstox 6.0.3 / 6.4.0 dependency-convergence failure; arbitrary
network/build failures do not count as success.

To route all scenarios through a configured Maven repository, the AWS pipeline
passes `--settings /path/to/settings.xml`. The normal local command retains its
original direct-repository settings. The override is recorded in command logs;
credentials must be environment references, never literal values in the file.

## Optional development container

With Docker and the VS Code Dev Containers extension installed, open this folder
and select **Dev Containers: Reopen in Container**. The container provides
JDK 11, Maven 3.9.9, Python 3.13, AWS CLI, GitHub CLI (`gh`) and Docker CLI. On
creation it recreates the workspace `.venv` and installs
`aws/requirements-dev.txt`; this replaces any existing host `.venv`. Ruff and
cfn-lint are available on the terminal PATH. It
also installs markdownlint-cli2 0.17.2, Hadolint 2.15.1 and the Python and Ruff
VS Code extensions. VS Code defaults to
the container's `.venv` interpreter; if an interpreter was already selected, choose
`.venv/bin/python` using **Python: Select Interpreter**. Rebuild the container
after changing its configuration; rerun
`.venv/bin/python -m pip install -r aws/requirements-dev.txt`
after changing the requirements. The base image and dev container features can
receive updates when rebuilt.
GitHub CLI authentication is separate; run `gh auth login` if needed.

Docker commands use the host Docker engine and require it to be running. Socket
access grants powerful control over the host; use a trusted workspace. The
container and host must use the same architecture. For rootless Docker or
workspace bind mounts, see the
[Docker-outside-of-Docker feature documentation](https://github.com/devcontainers/features/blob/main/src/docker-outside-of-docker/README.md).
To provide local AWS credentials, copy `.env.example` to `.env` before opening
or rebuilding the container, then fill in the allocated access key, secret key
region and `AWS_PROFILE` (for example, `lightwell`). Add `AWS_SESSION_TOKEN` as
well when using temporary credentials.
The devcontainer passes these values into the container as environment
variables and configures the named AWS profile on startup. The profile
reads the environment credentials without copying them into the AWS
credentials file. AWS CLI and the sample use `AWS_PROFILE` by default. Verify
with `aws sts get-caller-identity` or
`aws sts get-caller-identity --profile "$AWS_PROFILE"`. Rebuild the container
after changing `.env` or the container configuration. An existing profile with
saved credentials can override the environment-backed provider;
remove those saved credentials if they should not be used.
The `.env` file is gitignored. Do not commit credentials or bake them into the
image; environment variables are available to processes running in the
container, so use credentials intended for local development and least
privilege.

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

## AWS integration and validation

The integration is implemented under `aws/`. A run passed in ap-southeast-1
with the current private networking, log encryption and access logging in
place and Inspector skipped; rehearse in the target account before presenting.
See the [AWS setup guide](aws/README.md) for the recorded build and its limits.
The setup guide covers required permissions, Inspector enablement, artifact
publication, evidence, costs and cleanup. The package does not enforce a
monetary cap.

Local validation includes three Java 11 runtime containers with networking
disabled and a read-only filesystem. This supplements the original build
validation; it does not establish Inspector recognition or AWS IAM correctness.

Run the offline checks after installing `aws/requirements-dev.txt` (already
installed in the development container):

```sh
ruff check .
ruff format --check .
python3 -m unittest discover -s tests -v
cfn-lint aws/template.yaml
markdownlint-cli2 "**/*.md"
hadolint .devcontainer/Dockerfile
```

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

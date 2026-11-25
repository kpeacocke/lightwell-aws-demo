# AWS integration: setup and demonstration

## Status

The deployment template and integration code are implemented. Three runtime
containers have passed local Java 11 smoke checks with no network and a
read-only filesystem. CloudFormation linting and offline failure-path tests
pass. On 25 November 2026, one run in ap-southeast-1 passed CodeArtifact
publication, all scenarios, ECR image creation and both Fargate tasks with
Inspector skipped. Inspector results, backport recognition and stack cleanup
remain unverified. Results in other accounts are not guaranteed.

## What runs

```text
Red Hat demo patch --explicit publication--> CodeArtifact + Maven Central
                                                   |
Four scenario POMs --------------------------> CodeBuild
                                                   |
                             three runtime images + SBOMs + checks
                                                   |
                                                  ECR
                                                 /   \
                                         Inspector   Fargate
                                               |       |
                                           S3 evidence + CloudWatch
```

This implements the deck's CodeArtifact path by publishing one exact patch,
not by configuring a generic remote proxy. All scenario builds and plugin
resolution use a CodeArtifact mirror. The locally maintained security BOM is
installed into the Lightwell build's fresh cache, as in Derek's demonstration.
The downstream patch JAR must match the vendor JAR hash. Existing identical
published artifacts are reused; conflicting content stops the build.
The build configures origin controls for `com.fasterxml.woodstox:woodstox-core`
to allow both direct publication and upstream ingestion, so Maven Central
versions and the Lightwell patch can coexist. This increases dependency
substitution risk; use a dedicated demo repository and review this setting before
using the approach elsewhere. Package group restrictions can still block access.

The baseline, conventional and Lightwell images share the same resolved base
image digest. Runtime dependencies are copied into the images. Each is tested
with Docker networking disabled before upload. Both successful remediation
versions then run as one-shot Fargate tasks by immutable image digest.

Inspector results are recorded independently. Build success does not require a
clean vulnerability report. A missing finding is labelled NOT_REPORTED, never
"fixed". Incomplete scans fail the run and are labelled INCONCLUSIVE.
The optional no-Inspector mode records scans as SKIPPED, not clean.
The package inventory and SBOM are separate from Inspector's own coverage;
a successful scan alone does not prove recognition of the Lightwell backport.

## Prerequisites

- A dedicated demo AWS account and selected Region with these services enabled.
- Python 3.10+ and AWS credentials, preferably an existing SSO profile.
- Permission to provision the CloudFormation resources and their IAM roles.
- Amazon Inspector ECR scanning enabled by the account administrator, unless
  explicitly running without Inspector.
- Approval to publish this exact Red Hat demo artifact into the account.
  Repository availability is not a redistribution licence.
- A cost limit agreed with the account owner. This package does not enforce a
  monetary cap. CodeBuild, Fargate, Inspector, storage, logs and public IPv4
  addresses can incur charges. There is no NAT gateway or always-on app task.

Use a virtual environment outside the source archive:

```sh
python3 -m venv .venv
.venv/bin/pip install -r aws/requirements.txt
```

All commands below run from the repository root. The dev container configures
the profile named by `AWS_PROFILE` in `.env`; outside it, set `AWS_PROFILE` to
an existing profile instead. Replace the Region in the examples with an
approved value. No AWS action is performed by the `package` command.

## Package locally

```sh
.venv/bin/python aws/demo.py package
```

This writes `.aws-demo/source.zip` and prints its SHA-256. The upload allowlist
contains only application sources, explicit Maven settings, the manifest and
build code. It excludes evidence, Git history, editor settings and credentials.
A source-manifest mismatch prevents packaging.

## Deploy

```sh
.venv/bin/python aws/demo.py deploy \
  --profile "$AWS_PROFILE" --region us-east-1 --stack lightwell-demo
```

The template creates CodeArtifact, ECR, an encrypted private S3 bucket,
CodeBuild, an ECS cluster, logs, scoped roles and a small VPC. It creates no
running Fargate task until a build starts. The task subnet has an internet route
for image pulls and logging; tasks receive public IPs but have no inbound
security-group rules, application listener, load balancer or task IAM role.

CodeBuild uses a privileged managed Linux image for Docker builds. Do not run
untrusted pull-request code in this project. ECS does not support resource-level
permissions for task-definition deregistration, so the build role may
deregister any task definition in the selected Region; the demo only deregisters
its own. The runtime base can be pinned:

```sh
.venv/bin/python aws/demo.py deploy \
  --profile "$AWS_PROFILE" --region us-east-1 --stack lightwell-demo \
  --runtime-base 'public.ecr.aws/amazoncorretto/amazoncorretto@sha256:DIGEST'
```

The default is the Corretto 11 tag. Every run resolves it once and records the
actual digest. The CodeBuild managed image and Maven plugin transitives can
also change; this package is not a fully hermetic build.

## Configure scanning

The stack does not silently change account-wide Inspector settings. For the
default scanned run, have the administrator enable Amazon Inspector ECR enhanced
scanning first. Then:

```sh
.venv/bin/python aws/demo.py enable-scanning \
  --profile "$AWS_PROFILE" --region us-east-1 --stack lightwell-demo
```

This adds only a rule for the demo repository to an already-enhanced registry,
if needed, and saves the previous configuration in S3. It refuses to convert a
BASIC registry or overwrite a full rule set. In the latter case, add the demo
filter to an existing rule through ECR settings. The default run command and
build both check repository coverage before proceeding. Skip this step if
explicitly running without Inspector.

## Run the integration

After confirming artifact publication permission:

```sh
.venv/bin/python aws/demo.py run \
  --profile "$AWS_PROFILE" --region us-east-1 --stack lightwell-demo \
  --allow-demo-artifact-publication --wait
```

The command uploads the source ZIP, starts CodeBuild and follows its status.
It prints the build ID, CloudWatch links and S3 evidence location. To reconnect:

```sh
.venv/bin/python aws/demo.py status \
  --profile "$AWS_PROFILE" --region us-east-1 --build-id BUILD_ID
```

If Inspector cannot be enabled, add `--skip-inspector` to the `run` command.
This explicit per-build option skips coverage checks and Inspector calls; it does
not change account scanning settings or disable any existing ECR scanning. The
build still publishes the demo artifact, builds images and runs Fargate tasks.
Its `integration.json` outcome is `INTEGRATION_PASS_INSPECTOR_SKIPPED`, and
`scan-comparison.json` marks every image `SKIPPED`. No vulnerability scan or
backport recognition is established by this mode.

CodeBuild runs four scenario checks, publishes three images and runs the two
remediation tasks sequentially. The scan wait is bounded to ten minutes; task
execution is bounded to five minutes per task. The overall build limit is one
hour. Treat a scan deadline as unresolved evidence, not a clean scan.

## What to show during the presentation

1. **CodeArtifact:** `woodstox-core:6.0.3.rhlw-00001` and its published assets.
   Explain explicit publication from Red Hat, not a native proxy integration.
2. **CodeBuild:** four expected scenario outcomes, including the intentional
   convergence failure; show the actual dependency differences.
3. **ECR:** three image tags and immutable digests tied to the same run.
4. **Inspector:** if enabled, show scan state and findings for each digest. Any
   missing target finding requires coverage and advisory review before claiming
   a fix. Otherwise, state clearly that Inspector was skipped.
5. **ECS and CloudWatch:** both remediation tasks stopped successfully and
   printed PX-1001, 129.99 USD and APPROVED.
6. **S3:** the evidence archive ties source, packages, images, tasks and scans
   together. This is demo evidence, not SLSA certification.

Complete a rehearsal before presenting. Recorded results must be labelled with
the actual AWS build ID and time. Do not substitute local tests for AWS output.

## Evidence and failure handling

The CodeBuild artifact ZIP contains the original scenario reports and `aws/`:

- `integration.json`: stages, task results and overall outcome.
- `codeartifact.json`: package source/destination and vendor hashes.
- `images.json` and `runtime-base.json`: deployed digests and runtime base.
- Per-scenario runtime inventories, CycloneDX SBOMs and container smoke logs.
- `scan-comparison.json`; with Inspector enabled, per-image Inspector pages and
  resource coverage. In skip mode, per-image results are `SKIPPED`.
- Task launch/status JSON and captured CloudWatch payment output.

Tokens are held in environment variables; settings reference the variable rather
than containing the token. Do not enable Maven debug logging. Review evidence
before sharing it; it contains account and resource identifiers.

An integration success is labelled
`INTEGRATION_PASS_SECURITY_REVIEW_REQUIRED`; it is not a CVE-remediation verdict.
Without Inspector, success is labelled `INTEGRATION_PASS_INSPECTOR_SKIPPED`;
it is not evidence that images are clean or a vulnerability is fixed.
CloudFormation schema and mocked SDK checks cannot prove service permissions or
runtime behaviour. Live acceptance in the target account is still required.

## Cleanup

```sh
.venv/bin/python aws/demo.py cleanup \
  --profile "$AWS_PROFILE" --region us-east-1 --stack lightwell-demo
```

Cleanup refuses to proceed while a build is active. It stops remaining tasks,
deregisters active demo task definitions and removes the exact scanning rule
created by the helper if that rule is still unchanged. It deletes the stack,
including demo images, packages, logs and networking.

The evidence bucket is retained; objects expire after 30 days. Delete that
bucket separately when its evidence is no longer needed. Inspector remains
enabled, and manually configured scanning rules remain under administrator
control. Inactive task-definition revisions can remain as AWS history.

If a build is force-stopped, run cleanup to catch any task left behind.
Do not delete the stack before stopping its tasks.

## Local checks

```sh
ruff check .
ruff format --check .
python3 -m unittest discover -s tests -v
cfn-lint aws/template.yaml
```

Install `aws/requirements-dev.txt` for these Python and CloudFormation tools.
The tests use fake credentials and mocked responses; they do not contact an
AWS account. Markdown linting is checked separately with markdownlint-cli2.

## References

- [Maven with CodeArtifact][maven]
- [CodeArtifact supported external connections][connections]
- [Inspector ECR scanning][scanning]

[maven]: https://docs.aws.amazon.com/codeartifact/latest/ug/maven-mvn.html
[connections]: https://docs.aws.amazon.com/codeartifact/latest/ug/external-connection.html
[scanning]: https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html

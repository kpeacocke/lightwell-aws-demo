# Local integration validation

## Actual runtime checks

All three images passed on the local Docker engine using the same Amazon
Corretto Java 11 base and Linux AMD64 runtime target. Each ran with Docker
networking disabled, a read-only filesystem and an unprivileged user.

| Scenario | Runtime check |
| --- | --- |
| Baseline | PASS |
| Conventional | PASS |
| Lightwell | PASS |

Each printed transaction PX-1001, amount 129.99 USD and status APPROVED.
Runtime JAR hashes and output are in
[local-runtime-results.json](local-runtime-results.json).
These images used the previously validated local build artifacts. This is a
runtime packaging check, not a new CodeBuild run or CodeArtifact validation.

## Offline checks

- CloudFormation schema/resource validation with cfn-lint.
- Ruff lint and formatting checks for Python.
- Markdown linting, excluding LICENSE.
- Source manifest and source ZIP allowlist checks.
- Unit tests for expected build outcomes, scan deadlines, incomplete scans,
  absent findings, Fargate failures, successful task handling and SDK request
  shapes, and CodeArtifact identical/conflicting asset handling.

The tests use mocked AWS responses and fake credentials. They do not prove that
IAM policies are sufficient or that live services accept the complete workflow.

## AWS validation

These local checks created no AWS resources. A subsequent live run passed
CodeArtifact publication and resolution, CodeBuild scenarios, ECR push and
Fargate execution with CloudWatch output in ap-southeast-1, with Inspector
skipped. Inspector coverage, Lightwell patch recognition and stack cleanup
remain unverified. The live run preceded the current private networking,
customer-managed log encryption and S3 access-logging changes; those changes
have not been live-validated.

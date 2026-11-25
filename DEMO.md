# AWS and Lightwell demonstration

## Position in the deck

Present this demonstration immediately after **Integrating Lightwell Updates**.
It provides one concrete Java example behind the broader AWS and Lightwell
architecture. The local demonstration is validated. One AWS run passed with
Inspector skipped; rehearse in the target account before presenting live.

Opening statement:

> We will compare two ways of changing dependencies in one Java application.
> The conventional path upgrades Jackson and Woodstox. The Lightwell path
> retains Jackson and selects a patched Woodstox build. We will show the actual
> dependency changes, build checks and sample output, then identify where AWS
> services can fit. Dependencies remain in both paths.

## Demonstration scope

- **Implemented:** four isolated Maven scenarios, dependency-version checks,
  payment-output checks, artifact hashes and local evidence reports.
- **Recorded validation:** all four expected outcomes passed on 25 November
  2026 using Maven 3.10.2 and Java 27, targeting Java 11 bytecode.
- **Manual extension:** Derek's Trivy and sample-VEX sequence. The automated
  runner does not perform these scans.
- **Live-validated once:** CodeArtifact publication, CodeBuild, ECR and Fargate
  with Inspector skipped. Inspector remains unverified. See [AWS setup](aws/README.md).
- **Future:** Transform and Continuum exercises.
- **Not established:** general compatibility, exploit remediation, migration
  acceleration, token savings, SLSA conformance or native Lightwell integration
  with any AWS service.

The optional development container provides a different toolchain. Show the
actual run's `toolchain.txt`; do not attribute old evidence to a new
environment.

## Choose local or AWS execution

For the AWS presentation, follow [aws/README.md](aws/README.md): deploy the
stack, configure Inspector or explicitly skip it, publish the source package and
start CodeBuild.
Use the real build ID, image digests, findings and task output in the sequence
below. The local command is a rehearsal of the Maven scenarios, not a substitute
for AWS evidence. See [local checks](aws/LOCAL-VALIDATION.md) for the boundary.

## Prepare before presenting

Run from the repository root with Maven, a suitable JDK and Python installed:

```sh
python3 run_scenarios.py --work-dir /tmp/lightwell-demo
```

The runner prints the evidence directory for this invocation. Open its
`REPORT.md`, `results.json` and `toolchain.txt`. Check that all four scenarios
passed their expected outcomes. Keep this exact directory open during the
presentation; do not silently substitute another run.

Each scenario uses an initially empty Maven cache. Complete downloads before a
short presentation. If showing prepared evidence, identify it as a recorded run
and show its timestamp and toolchain. Use `--scenario` for an individual rerun.

For manual Maven and scanner commands, use [Derek's walkthrough][walkthrough].
The automated path below does not modify the checked-in POM or Maven settings.

## Presenter sequence

Allow approximately ten minutes for the local sequence and AWS discussion.
Build duration is additional; recorded evidence avoids unpredictable downloads.

### 1. Establish the application and baseline

Deck connection: **How Enterprises Build Today**.

Show `source/src/main/java/com/parasol/paymentgateway/App.java`, then
`source/pom_0_original.xml`. This is a fixed-input XML parser, not a network
payment service. Show these files from the chosen evidence directory:

- `baseline/verify.log`: successful build.
- `baseline/dependency-tree.log`: Jackson 2.10.2 and Woodstox 6.0.3.
- `baseline/application.log`: PX-1001, 129.99 USD, APPROVED.

What this proves: the starting application resolves dependencies and runs its
sample input. It does not establish vulnerability exploitability.

AWS insertion: CodeBuild builds the same source and ECR stores its runtime
image. Inspector scanning is optional and was skipped in the validated run.
The local runner does not execute these services.

### 2. Show the constrained upgrade failure

Deck connection: the problem addressed by **Integrating Lightwell Updates**.

Show `source/pom_1_pinned_woodstox.xml` and
`pinned-failure/verify.log`. Identify both Woodstox versions in the Enforcer
error. The scenario is marked PASS because this specific failure was expected.

What this proves: the dependency-convergence policy rejects the direct pin.
It does not prove binary incompatibility, runtime failure or a migration block.
Show the existing Enforcer exceptions rather than hiding them.

### 3. Show the conventional working alternative

Show `source/pom_2_pinned_upgrade_jackson.xml`, then the conventional scenario's
`verify.log`, `dependency-tree.log` and `application.log`.

What this proves: Jackson 2.13.5 with Woodstox 6.4.0 builds and passes the same
sample-output check. Compare the full tree with baseline; the changes extend
beyond Woodstox. These are demonstration versions, not current production
version recommendations.

Proposed later insertion: Transform custom generates a reviewed upgrade
candidate and submits it to the same checks. The current runner selects a
prepared POM; it does not use AI to discover or generate a fix.

### 4. Show the targeted Lightwell change

Deck connection: **Securing with Lightwell** and **Integrating Lightwell
Updates**.

Show `source/pom_3_lightwell.xml`, `source/packaging-pom/pom.xml` and
`config/lightwell-settings.xml`. Then show the Lightwell scenario's BOM install,
build, dependency-tree and application logs.

What this proves: a build can retrieve the patched Woodstox artifact, retain
Jackson 2.10.2 and pass the same sample-output check. In the recorded
comparison,
only Woodstox's resolved version changes from baseline. The application source
is unchanged. Compatibility beyond this sample remains untested.

Local execution retrieves the patch directly from Red Hat's demo repositories.
The AWS pipeline explicitly publishes that patch to CodeArtifact, then resolves
all scenario dependencies through CodeArtifact. It checks that the downstream
patch hash matches the vendor bytes. This is custom publication code, not an
Artifactory-style proxy or a claimed native Lightwell service integration.

### 5. Explain the security evidence boundary

Deck connection: **Validate, Deliver** in **AWS + Red Hat Lightwell**.

Show the artifact hashes in `results.json` and identify the exact patched
version. Hashes identify downloaded bytes; they do not authenticate a vendor
advisory or prove a security fix.

If presenting Trivy, preflight the manual sequence separately and retain both
raw and VEX-assisted results. Label `lightwell-woodstox-core.openvex` as a
sample
assertion. Never use its filtering effect as independent remediation proof.

Optional AWS insertion, not yet live-validated: compare Inspector scans of
baseline, conventional and Lightwell images by immutable digest. Confirm package
coverage
before interpreting absence of a finding. Preserve any remaining finding;
automatic suppression is not implemented.

### 6. Close with a bounded AWS validation proposal

Deck connection: **Four Strategic Wins for AWS**, followed by the
**Identify, Assess, Prove, Engage** customer call to action.

Closing statement:

> This example demonstrates a smaller resolved dependency change and successful
> sample execution. Next we want to validate its delivery through AWS builds,
> image scanning and execution. A joint POC on one representative customer
> application can measure remediation effort and test whether this helps its
> modernisation programme.

Do not report the four strategic wins as measured outcomes of this toy example.

## AWS architecture status

The validated local execution path is:

```text
Pinned application + scenario POM
              |
              v
Local Maven build <-- Maven Central / Lightwell demo repositories
              |
              v
Dependency checks + payment smoke check --> Local evidence
```

The implemented AWS path, validated once with Inspector skipped, is:

```text
CodeArtifact --> CodeBuild --> ECR --> Inspector findings
                       |          |
                       |          +--> One-shot ECS/Fargate execution
                       v                         |
                   S3 evidence              CloudWatch Logs
```

CloudFormation and IAM provide the deployment definition and roles. The files
exist under `aws/`; the successful run created AWS resources.

### CodeArtifact delivery

The deck's CodeArtifact arrow now has an implemented custom publication path.
The pipeline retrieves one exact demo patch from Red Hat and publishes its JAR
and POM to CodeArtifact. Maven Central supplies standard upstream dependencies.
All scenario builds use the resulting CodeArtifact repository as a mirror.

This is not an arbitrary remote proxy. The supported [external
connections][codeartifact] do not list Lightwell. Confirm publication permission
and validate
this path in the target account before describing it as demonstrated.
The downstream patch must match the vendor checksum; credentials are not saved
in the source ZIP or evidence. Existing conflicting assets stop the build.

### Live acceptance gates

1. Reproduce the validated CodeBuild and CodeArtifact run in the target account.
2. Establish Inspector coverage and actual target-CVE findings for each image.
   An unrecognised patch is a recorded integration gap, not a suppressed
success.
3. Reproduce builds in CodeBuild and execute the successful remediation images
   as one-shot Fargate tasks. Retain image digests, checks and runtime output.
4. Exercise the included deployment and cleanup commands after account, Region
   and service access are agreed. Cleanup remains unverified.

Transform, Continuum, Security Hub and Audit Manager are later investigations.
Neither this demo nor a collection of logs establishes SLSA conformance.
Migration acceleration and token savings need a separately measured pilot.

## Slide wording to align before presenting

- **High Level Overview:** distinguish Lightwell repositories from CodeArtifact;
  label explicit publication as validated once with Inspector skipped.
- **Integrating Lightwell Updates:** distinguish artifact selection, build
  orchestration and scanning from automatic remediation generation.
- **AWS + Red Hat Lightwell:** distinguish implemented paths from future
integrations;
  do not promise patch recognition, exploit validation or automatic suppression.
- **Four Strategic Wins:** describe benefits as hypotheses for joint validation;
  request authoritative product evidence for any provenance-level claim.
- **Demonstration:** use the six-step agenda above; identify what is recorded,
  live, manual or proposed before showing results.
- **Customer engagement:** retain the one-application POC request. Have the
  product owner confirm assessment offers, coverage and commercial availability.

[walkthrough]: source/DEMOSCRIPT.md
[codeartifact]: https://docs.aws.amazon.com/codeartifact/latest/ug/external-connection.html

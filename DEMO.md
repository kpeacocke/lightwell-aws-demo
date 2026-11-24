# AWS and Lightwell demonstration

## Position in the deck

Present this demonstration immediately after **Integrating Lightwell Updates**.
It provides one concrete Java example behind the broader AWS and Lightwell
architecture. The current release is a local demonstration; AWS integrations
are proposed work, not live features of this package.

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
- **Proposed:** CodeBuild, ECR/Inspector and Fargate integration; CodeArtifact
  distribution investigation; later Transform and Continuum exercises.
- **Not established:** general compatibility, exploit remediation, migration
  acceleration, token savings, SLSA conformance or native Lightwell integration
  with any AWS service.

The optional development container provides a different toolchain. Show the
actual run's `toolchain.txt`; do not attribute old evidence to a new environment.

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

Proposed AWS insertion: CodeBuild builds the same source; an ECR image contains
its runtime JARs; Inspector scans the image. None is executed by this package.

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
Jackson 2.10.2 and pass the same sample-output check. In the recorded comparison,
only Woodstox's resolved version changes from baseline. The application source
is unchanged. Compatibility beyond this sample remains untested.

The dependency source is Red Hat's public demo Maven repositories, accessed
directly. This demonstration does not route packages through CodeArtifact.
Derek's recording additionally demonstrates Artifactory configuration.

### 5. Explain the security evidence boundary

Deck connection: **Validate, Deliver** in **AWS + Red Hat Lightwell**.

Show the artifact hashes in `results.json` and identify the exact patched
version. Hashes identify downloaded bytes; they do not authenticate a vendor
advisory or prove a security fix.

If presenting Trivy, preflight the manual sequence separately and retain both
raw and VEX-assisted results. Label `lightwell-woodstox-core.openvex` as a sample
assertion. Never use its filtering effect as independent remediation proof.

Proposed AWS insertion: compare completed Inspector scans of the baseline,
conventional and Lightwell images by immutable digest. Confirm package coverage
before interpreting absence of a finding. Preserve any remaining finding;
automatic suppression is not part of the proposed first release.

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

The implementation today is:

```text
Pinned application + scenario POM
              |
              v
Local Maven build <-- Maven Central / Lightwell demo repositories
              |
              v
Dependency checks + payment smoke check --> Local evidence
```

The proposed first AWS increment is:

```text
Same scenarios --> CodeBuild --> ECR --> Inspector findings
                       |          |
                       |          +--> One-shot ECS/Fargate execution
                       v                         |
                   S3 evidence              CloudWatch Logs
```

CloudFormation and IAM would provide reproducible setup and scoped access.
This architecture is a plan; no AWS deployment files or resources exist here.

### CodeArtifact decision

The deck places CodeArtifact prominently in package delivery. Label that arrow
**proposed integration** and keep the Lightwell source repositories distinct
from the customer's CodeArtifact repository.

[CodeArtifact external connections][codeartifact] list supported public
repositories; Lightwell is not listed. Do not assume an arbitrary remote proxy
connection works like Artifactory. An approved publication or synchronisation
path needs its own validation of permissions, exact package coordinates,
checksums, metadata, provenance and reproducible downstream resolution.

Keep that investigation separate from the first AWS execution demonstration.
If the deck must claim delivery through CodeArtifact, complete that work before
presenting the arrow as implemented.

### Acceptance gates for the next increment

1. Package the three successful scenarios with their actual runtime JARs and
   verify execution without dependency downloads at startup.
2. Establish Inspector coverage and actual target-CVE findings for each image.
   An unrecognised patch is a recorded integration gap, not a suppressed success.
3. Reproduce builds in CodeBuild and execute the successful remediation images
   as one-shot Fargate tasks. Retain image digests, checks and runtime output.
4. Add deployment and cleanup automation after the account, Region and service
   access are agreed. AWS account setup is deferred.

Transform, Continuum, Security Hub and Audit Manager are later investigations.
Neither this demo nor a collection of logs establishes SLSA conformance.
Migration acceleration and token savings need a separately measured pilot.

## Slide wording to align before presenting

- **High Level Overview:** distinguish Lightwell repositories from CodeArtifact;
  label the proposed distribution boundary.
- **Integrating Lightwell Updates:** distinguish artifact selection, build
  orchestration and scanning from automatic remediation generation.
- **AWS + Red Hat Lightwell:** label the end-to-end workflow as a target design;
  do not promise patch recognition, exploit validation or automatic suppression.
- **Four Strategic Wins:** describe benefits as hypotheses for joint validation;
  request authoritative product evidence for any provenance-level claim.
- **Demonstration:** use the six-step agenda above; identify what is recorded,
  live, manual or proposed before showing results.
- **Customer engagement:** retain the one-application POC request. Have the
  product owner confirm assessment offers, coverage and commercial availability.

[walkthrough]: source/DEMOSCRIPT.md
[codeartifact]: https://docs.aws.amazon.com/codeartifact/latest/ug/external-connection.html

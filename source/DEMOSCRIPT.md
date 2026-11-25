# Demo Script for Lightwell Code Remediation Demonstration

## Synopsis

This demonstration uses the small Java application "Parasol Payment Gateway"
to show how a vulnerability in a transitive dependency can broaden the scope
of a conventional dependency upgrade, and how Lightwell offers a targeted
patched dependency instead.

The application directly depends on Jackson XML, which brings in Woodstox.
The example focuses on CVE-2022-40152. The failed upgrade demonstrates Maven
dependency-convergence enforcement, not proven runtime incompatibility.

This is a locally edited adaptation of Derek Waters' demo script. The Java
application and POM variants remain unchanged. Their Enforcer exceptions,
including the exception for the Lightwell patch version, remain in place.

## Fit with the AWS slide deck

Use the [AWS presenter flow](../DEMO.md) for the short presentation. Place this
technical walkthrough after **Integrating Lightwell Updates**. The steps below
retain Derek's manual build and scanner flow; they do not execute AWS services.

- **How Enterprises Build Today:** show the baseline dependency tree and output.
- **Integrating Lightwell Updates:** compare the failed direct pin, conventional
  upgrade and Lightwell BOM path using the same sample-output checks.
- **Securing with Lightwell:** identify direct Maven access to Red Hat's demo
  repositories for local runs. The AWS path publishes the patch to CodeArtifact
  explicitly; a live run validated this path with Inspector skipped.
- **Validate, Deliver:** distinguish raw scanner findings, sample-VEX filtering
  and the future Inspector image comparison. A successful build is not a
  security-fix attestation.
- **Four Strategic Wins:** close with a one-application AWS POC proposal, not
  claims of proven migration acceleration, token savings or SLSA conformance.

The implemented AWS extension uses CodeBuild, ECR, Inspector and Fargate; see
[the AWS setup guide](../aws/README.md). These paths still require a live account
rehearsal. Keep Transform and Continuum as later exercises. The local automated
runner validates Maven builds; `aws/pipeline.py` coordinates AWS execution.

## Demo Preparation

Run these manual steps from this directory (`source/` in the local package).
The automated runner in the parent directory uses isolated settings and caches;
the manual instructions below use your normal Maven configuration.

1. Install a JDK supporting Java 11 compilation and install Maven separately.
2. Install [Trivy][trivy-install] if you want to demonstrate scanning.
3. Configure Maven to include the Lightwell repositories. Merge the following
   profiles into `~/.m2/settings.xml`, preserving any existing settings:

   ```xml
   <settings>
     <profiles>
       <profile>
         <id>lightwell-validated</id>
         <repositories>
           <repository>
             <id>lightwell-validated</id>
             <name>Red Hat Lightwell Network - Validated</name>
             <url>https://packages.redhat.com/lightwell/public-lightwell-demo/java/validated/</url>
             <releases>
               <enabled>true</enabled>
             </releases>
             <snapshots>
               <enabled>false</enabled>
             </snapshots>
           </repository>
         </repositories>
       </profile>
       <profile>
         <id>lightwell-remediated</id>
         <repositories>
           <repository>
             <id>lightwell-remediated</id>
             <name>Red Hat Lightwell Network - Remediated</name>
             <url>https://packages.redhat.com/lightwell/public-lightwell-demo/java/remediated/</url>
             <releases>
               <enabled>true</enabled>
             </releases>
             <snapshots>
               <enabled>false</enabled>
             </snapshots>
           </repository>
         </repositories>
       </profile>
     </profiles>
     <activeProfiles>
       <activeProfile>lightwell-remediated</activeProfile>
       <activeProfile>lightwell-validated</activeProfile>
     </activeProfiles>
   </settings>
   ```

4. Install the local security BOM:

   ```bash
   mvn -f packaging-pom/pom.xml install
   ```

5. Restore the initial POM before each demonstration:

   ```bash
   cp pom_0_original.xml pom.xml
   ```

For a genuinely clean-cache comparison, use the automated runner instead of
relying on this manual walkthrough's shared Maven cache. The runner validates
the source manifest, so restore `pom.xml` to `pom_0_original.xml` after manually
switching scenarios and before running automated validation.

## Demo Process and Suggested Description

### The Initial Build

1. Show `App.java`. It parses fixed payment XML and prints the payment details.
2. Show `pom.xml` and its direct dependency on Jackson XML 2.10.2.
3. Build and show the dependency tree, including Woodstox 6.0.3:

   ```bash
   mvn clean verify
   mvn dependency:tree
   ```

4. Run the application:

   ```bash
   mvn compile exec:java
   ```

5. Confirm transaction `PX-1001`, amount `129.99 USD` and status `APPROVED`.

### The CVE Issue

1. Run the security scanner and retain its actual output:

   ```bash
   trivy -q fs .
   ```

2. Identify CVE-2022-40152 for Woodstox. Open its [NVD entry][cve].
3. Show the [Woodstox versions][woodstox] and the conventional fix in 6.4.0.
4. Select the POM that directly pins Woodstox 6.4.0:

   ```bash
   cp pom_1_pinned_woodstox.xml pom.xml
   mvn clean verify
   ```

5. Show the expected Maven Enforcer dependency-convergence error. Explain that
   this is a policy conflict between declared dependency paths, not proof that
   the application would fail at runtime.

### The Upgrade Problem

1. Show that [Jackson XML 2.13.5][jackson] declares Woodstox 6.4.0.
2. Select the conventional upgrade and validate it:

   ```bash
   cp pom_2_pinned_upgrade_jackson.xml pom.xml
   mvn clean verify
   mvn dependency:tree
   mvn compile exec:java
   ```

3. Compare the dependency trees. The conventional fix changes Jackson and other
   resolved dependencies as well as Woodstox.
4. Explain the additional validation scope. The sample output is a smoke check,
   not a comprehensive compatibility test.

### The Lightwell Solution

1. Open the [Lightwell demo][lightwell-demo] and show the Woodstox 6.0.3
   remediation in the Java remediated repository.
2. Select the Lightwell POM:

   ```bash
   cp pom_3_lightwell.xml pom.xml
   ```

3. Show the Maven repository settings, the retained Jackson 2.10.2 dependency,
   and the imported `com.parasol:security-bom:2026.09.18`.
4. Show `packaging-pom/pom.xml`, which selects Woodstox `6.0.3.rhlw-00001`.
   Explain that a platform team can maintain this BOM. Also disclose the
   existing Enforcer exceptions; do not present them as compatibility proof.
5. Build, inspect the resolved versions and run the application:

   ```bash
   mvn clean verify
   mvn dependency:tree
   mvn compile exec:java
   ```

6. Show `lightwell-woodstox-core.openvex`. This is a sample assertion for the
   demonstration, not independent proof of the security fix.
7. Compare the raw scan with a scan using the sample VEX:

   ```bash
   trivy -q fs .
   trivy -q --vex lightwell-woodstox-core.openvex fs .
   ```

8. Optionally filter the VEX-assisted output for the target CVE:

   ```bash
   trivy -q --vex lightwell-woodstox-core.openvex fs . | grep 40152
   ```

9. Explain any difference as scanner handling of the supplied assertion. Check
   that scanning completed successfully; an empty filtered result alone does
   not prove remediation, and unrelated findings may remain.
10. Restore the baseline POM when finished:

    ```bash
    cp pom_0_original.xml pom.xml
    ```

## Lens Stretch Goal

Generate a CycloneDX SBOM from the selected Maven scenario:

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom
```

Load `target/bom.json` or `target/bom.xml` into [Lightwell Lens][lens].

## Accompanying Resources

The original [slide deck][slides] includes links to the recording and requires
Red Hat internal access. The public [recording][recording] demonstrates the
Artifactory integration; this walkthrough uses direct Maven configuration.

[trivy-install]: https://trivy.dev/docs/latest/getting-started/installation/#install-script-official
[cve]: https://nvd.nist.gov/vuln/detail/cve-2022-40152
[woodstox]: https://mvnrepository.com/artifact/com.fasterxml.woodstox/woodstox-core
[jackson]: https://mvnrepository.com/artifact/com.fasterxml.jackson.dataformat/jackson-dataformat-xml/2.13.5/dependencies
[lightwell-demo]: https://console.redhat.com/lightwell/demo
[lens]: https://console.redhat.com/lightwell/lens
[slides]: https://docs.google.com/presentation/d/1H5tMrGp9n_Prq_jT571ntMGYDndQL4_o3tSdecbC4V8/edit
[recording]: https://www.youtube.com/watch?v=M7C1xSZd6ek

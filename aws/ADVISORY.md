# Read-only Lightwell advisory reconciliation

This step correlates Inspector's CVE-2022-40152 finding for
`com.fasterxml.woodstox:woodstox-core:6.0.3.rhlw-00001` with the vendor's public
OSV advisory. It does **not** suppress findings, establish exploitability,
validate signed provenance, or change `security_fix_verified: false`.

## Interfaces reviewed on 2026-11-25

- [Lightwell's OSV usage guide][guide] documents the exact Woodstox advisory,
  `RHLW-2026-403d1e66c95ef9bb`, and fetching it through OSV.
- [OSV GET by ID][get] documents
  `GET https://api.osv.dev/v1/vulns/{id}`. The exact advisory returned HTTP 200
  without credentials during implementation. This is the selected interface.
- [Lightwell's OpenAPI document][api] documents
  `https://console.redhat.com/api/lightwell/v0.1`, including `GET /advisories`
  with `cve_id`, `package_name`, `package_version`, `limit`, and `offset` filters.
  An unauthenticated request to `/advisories?cve_id=CVE-2022-40152` returned 401.
  The schema declares `RhIdentity` / `x-rh-identity`; that is not a documented
  end-user token-acquisition flow and must not be fabricated by this client.
  Authenticated access and account entitlements were not tested. This client
  does not implement that interface because public OSV supplies the needed data.
- [Lightwell artifact repository access][access] uses entitlement certificates.
  Artifact access is separate from public advisory access; neither a bearer
  token requirement nor artifact entitlement should be inferred for OSV.

The source advisory was checked at Lightwell feed commit
`b1e6eabbe1d7e87209cd5914ef6afde0222cb203`. It lists the target CVE in `upstream`,
the scoped ecosystem `Red Hat Lightwell:Maven`, base version `6.0.3`, and both
the fixed event and remediated version `6.0.3.rhlw-00001`. The live OSV record
also contained those fields. OSV may enrich metadata and modification times;
the implementation saves the actual response, retrieval time and SHA-256.

## Run against existing evidence without AWS changes

Python 3.10+ standard library is sufficient. From the repository root, with
`scan-comparison.json` and `images.json` extracted from the same build's evidence:

```sh
python3 aws/advisory.py \
  --scan-comparison evidence/aws/scan-comparison.json \
  --images evidence/aws/images.json \
  --output evidence/advisory-review-01
```

Choose a **new** output directory each time. Existing outputs are refused so a
failed lookup cannot inherit an earlier successful response. Input files are
read only; their SHA-256 values identify the evidence used. Keep the original
per-image `*-inspector.json` files alongside `scan-comparison.json`.

No Lightwell account, token, API key, AWS profile or new Python package is needed
for this command. Allow outbound HTTPS to `api.osv.dev:443` with trusted CA roots.
The endpoint and advisory ID are fixed deliberately; no credential-bearing URL
or arbitrary endpoint option is accepted. Requests have a 15-second socket
timeout and 1 MiB response limit, reject redirects, and do not retry. This is
a focused exact-release lookup, not general advisory discovery or a version
range evaluator. If the release changes, review the advisory and matching rules.

## Existing AWS demo integration

The normal pipeline runs the lookup after scan comparison and includes its
outputs in the existing S3 evidence archive. The source ZIP now includes
`aws/advisory.py`. No CloudFormation or IAM change is needed. Use the existing
run command to upload the updated code (this executes the full AWS demo):

```sh
.venv/bin/python aws/demo.py run \
  --profile lightwell-personal --region ap-southeast-1 --stack lightwell-demo \
  --allow-demo-artifact-publication --wait
```

`--skip-inspector` still marks Inspector correlation `UNAVAILABLE`; it cannot
establish a finding match. Existing incomplete-scan failures still stop the
pipeline before reconciliation. Network failures, 401/403/404/429/5xx responses,
invalid JSON and unusable advisory data produce explicit nonverified evidence;
they do not make the application integration fail or pass a security gate.
Input/output filesystem errors still fail the command. Exit code zero means
the evidence was written, **not** that a fix or correlation was verified.

## Evidence meanings

The new `lightwell-advisory/` directory in AWS evidence contains:

- `osv-response.json`: response bytes exactly as received when a bounded fetch
  succeeds, even if parsing subsequently fails. No HTTP error body is retained.
- `reconciliation.json`: retrieval source/time/hash, input hashes, target
  coordinates, advisory claim, Inspector finding ARNs/status/package paths,
  image digest binding and explicit verification limits.

- `lookup`: VERIFIED means an OSV JSON object was retrieved. UNAVAILABLE means
  retrieval or parsing failed.
- `vendor_advisory_claim`: VERIFIED means exact CVE, scoped package, base and
  fixed build match. Mismatch or withdrawal is UNVERIFIED; an unusable response
  is UNAVAILABLE.
- `inspector`: VERIFIED means the exact CVE and Java package/version are tied
  to the expected image digest. No exact match is UNVERIFIED; a missing, skipped
  or incomplete scan is UNAVAILABLE.
- `correlation`: VERIFIED requires both metadata checks above. It is UNAVAILABLE
  if either is unavailable, otherwise UNVERIFIED.
- `binary_provenance`: always UNVERIFIED.

`VERIFIED` is scoped to the named metadata check. The report always says
`action: REVIEW_REQUIRED`, `security_fix_verified: false` and
`inspector_findings_modified: false`. A matching advisory is a vendor claim,
not proof that the scanned binary contains the fix. Image binding matches
Inspector's reported digest to the build's recorded digest; it is not a signed
artifact-to-image provenance chain. A missing finding or advisory is not proof
of safety, lack of coverage, or a false positive. No suppressions or VEX are
generated, and no Inspector recommendation is replaced.

The checks require exact equality rather than comparing Maven versions or
stripping `.rhlw` suffixes. Fields must match on the same affected package
entry. Withdrawn records and records explicitly listing this build as affected
are not accepted. Other base-version branches cannot satisfy the match.

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Tests use synthetic records and mocked transport, covering identity mismatches,
withdrawal, cross-package fields, wrong image digests, skipped scans, absent
findings, errors, malformed/oversized responses, unchanged inputs and the
permanent security-verification boundary. Live public lookup and replay against
the supplied historical scan are separate from a fresh AWS execution.

[guide]: https://github.com/project-lightwell/lightwell-osv/blob/main/docs/README.md
[get]: https://google.github.io/osv.dev/api/get-v1-vulns/
[api]: https://github.com/content-services/content-sources-backend/blob/main/api/lightwell/openapi.json
[access]: https://docs.redhat.com/en/documentation/lightwell_network/current/get_started-authenticate_to_lightwell_network

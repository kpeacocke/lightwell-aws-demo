# Local build validation

Run: 20261124T220528172606Z

| Scenario | Result | Checks |
|---|---|---|
| baseline | PASS | build_success: True; dependency_versions: True; payment_output: True |
| pinned-failure | PASS | expected_convergence_failure: True |
| conventional | PASS | build_success: True; dependency_versions: True; payment_output: True |
| lightwell | PASS | bom_installed: True; build_success: True; dependency_versions: True; payment_output: True |

These are build, dependency and sample-output checks, not CVE exploit tests or AWS scanner validation.
Upstream Enforcer exceptions are unchanged. Target bytecode is Java 11; actual build/runtime versions are in toolchain.txt.

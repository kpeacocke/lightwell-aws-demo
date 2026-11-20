# Local build validation

Run: 20261124T220528172606Z

| Scenario | Result |
| --- | --- |
| baseline | PASS |
| pinned-failure | PASS |
| conventional | PASS |
| lightwell | PASS |

## Checks

### baseline

- `build_success`: True
- `dependency_versions`: True
- `payment_output`: True

### pinned-failure

- `expected_convergence_failure`: True

### conventional

- `build_success`: True
- `dependency_versions`: True
- `payment_output`: True

### lightwell

- `bom_installed`: True
- `build_success`: True
- `dependency_versions`: True
- `payment_output`: True

## Scope

These are build, dependency and sample-output checks,
not CVE exploit tests or AWS scanner validation.

Upstream Enforcer exceptions are unchanged. Target bytecode is Java 11;
actual build/runtime versions are in `toolchain.txt`.

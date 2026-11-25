#!/usr/bin/env python3
"""Reproduce scenarios without changing source or personal Maven settings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, List, Tuple

if TYPE_CHECKING:
    from typing import Callable, Dict, TypedDict

ROOT = Path(__file__).resolve().parent
SCENARIOS = {
    "baseline": ("pom_0_original.xml", "2.10.2", "6.0.3"),
    "pinned-failure": ("pom_1_pinned_woodstox.xml", "2.10.2", "6.4.0"),
    "conventional": ("pom_2_pinned_upgrade_jackson.xml", "2.13.5", "6.4.0"),
    "lightwell": ("pom_3_lightwell.xml", "2.10.2", "6.0.3.rhlw-00001"),
}


if TYPE_CHECKING:

    class CommandResult(TypedDict):
        label: str
        argv: List[str]
        exit_code: int

    class OptionalScenarioFields(TypedDict, total=False):
        runtime_jars: Dict[str, str]
        error: str

    class ScenarioResult(OptionalScenarioFields):
        name: str
        pom: str
        commands: List[CommandResult]
        checks: Dict[str, bool]
        status: str

    class OptionalReportFields(TypedDict, total=False):
        source_sha256: Dict[str, str]
        toolchain: str

    class Report(OptionalReportFields):
        run_id: str
        scratch: str
        source_commit: str
        scenarios: List[ScenarioResult]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_report(report: Report) -> str:
    """Render recorded results without rerunning or changing validation."""
    lines = [
        "# Local build validation",
        "",
        f"Run: {report['run_id']}",
        "",
        "| Scenario | Result |",
        "| --- | --- |",
    ]
    for result in report["scenarios"]:
        lines.append(f"| {result['name']} | {result['status']} |")
    lines += ["", "## Checks"]
    for result in report["scenarios"]:
        lines += ["", f"### {result['name']}", ""]
        for key, value in result["checks"].items():
            lines.append(f"- `{key}`: {value}")
    lines += [
        "",
        "## Scope",
        "",
        "These are build, dependency and sample-output checks,",
        "not CVE exploit tests or AWS scanner validation.",
        "",
        "Upstream Enforcer exceptions are unchanged. "
        "Target bytecode is Java 11;",
        "actual build/runtime versions are in `toolchain.txt`.",
    ]
    return "\n".join(lines) + "\n"


def check_successful_build(
    result: ScenarioResult,
    run: Callable[[str, List[str]], Tuple[int, str]],
    cache: Path,
    jackson: str,
    woodstox: str,
    code: int,
) -> None:
    result["checks"]["build_success"] = code == 0
    if code:
        raise RuntimeError("Build failed; inspect verify.log")
    code, tree = run(
        "dependency-tree",
        ["org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"],
    )
    result["checks"]["dependency_versions"] = code == 0 and all(
        token in tree
        for token in (
            f"jackson-dataformat-xml:jar:{jackson}:compile",
            f"woodstox-core:jar:{woodstox}:compile",
        )
    )
    code, output = run("application", ["compile", "exec:java"])
    result["checks"]["payment_output"] = code == 0 and all(
        re.search(pattern, output)
        for pattern in (
            r"Transaction Id:\s*PX-1001",
            r"Amount:\s*129\.99 USD",
            r"Status:\s*APPROVED",
        )
    )
    result["runtime_jars"] = {
        str(p.relative_to(cache)): digest(p)
        for p in sorted(cache.rglob("*.jar"))
        if any(
            s in str(p.relative_to(cache))
            for s in ("com/fasterxml/", "org/codehaus/woodstox/")
        )
    }


def run_scenario(
    name: str,
    scenario: Tuple[str, str, str],
    scratch: Path,
    evidence: Path,
    env: Dict[str, str],
    mvn: str,
    settings_override: Path | None,
) -> ScenarioResult:
    pom, jackson, woodstox = scenario
    project = scratch / name / "project"
    cache = scratch / name / "m2"
    logs = evidence / name
    logs.mkdir()
    shutil.copytree(ROOT / "source", project)
    shutil.copyfile(project / pom, project / "pom.xml")
    settings = ROOT / "config" / (
        "lightwell-settings.xml"
        if name == "lightwell"
        else "empty-settings.xml"
    )
    settings = settings_override or settings
    base = [
        mvn,
        "-B",
        "-ntp",
        "-s",
        str(settings),
        "-gs",
        str(ROOT / "config/empty-settings.xml"),
        f"-Dmaven.repo.local={cache}",
        "-Dstyle.color=never",
    ]
    result: ScenarioResult = {
        "name": name,
        "pom": pom,
        "commands": [],
        "checks": {},
        "status": "FAIL",
    }

    def run(
        label: str, goals: List[str], cwd: Path = project
    ) -> Tuple[int, str]:
        command = base + goals
        with (logs / f"{label}.log").open("w") as out:
            try:
                proc = subprocess.run(
                    command,
                    cwd=cwd,
                    env=env,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    timeout=600,
                )
                code = proc.returncode
            except subprocess.TimeoutExpired:
                out.write("\nRUNNER TIMEOUT after 600 seconds\n")
                code = 124
        result["commands"].append(
            {"label": label, "argv": command, "exit_code": code}
        )
        return code, (logs / f"{label}.log").read_text()

    try:
        if name == "lightwell":
            code, _ = run(
                "install-security-bom", ["install"], project / "packaging-pom"
            )
            result["checks"]["bom_installed"] = code == 0
            if code:
                raise RuntimeError("Security BOM installation failed")
        code, build = run("verify", ["clean", "verify"])
        if name == "pinned-failure":
            result["checks"]["expected_convergence_failure"] = (
                code not in (0, 124)
                and "Dependency convergence error" in build
                and "woodstox-core:jar:6.0.3" in build
                and "woodstox-core:jar:6.4.0" in build
                and "maven-enforcer-plugin" in build
            )
        else:
            check_successful_build(result, run, cache, jackson, woodstox, code)
        result["status"] = (
            "PASS"
            if result["checks"] and all(result["checks"].values())
            else "FAIL"
        )
    except Exception as error:
        result["error"] = str(error)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        help="Scratch location for fresh builds and Maven caches",
    )
    parser.add_argument(
        "--scenario", choices=["all", *SCENARIOS], default="all"
    )
    parser.add_argument(
        "--settings",
        type=Path,
        help=(
            "Optional Maven settings for all scenarios "
            "(for CodeArtifact builds)"
        ),
    )
    args = parser.parse_args()
    if args.settings:
        args.settings = args.settings.resolve()
        if not args.settings.is_file():
            parser.error("Settings file does not exist")
    manifest = json.loads((ROOT / "SOURCE-MANIFEST.json").read_text())
    for relative, expected in manifest["sha256"].items():
        path = ROOT / "source" / relative
        if not path.is_file() or digest(path) != expected:
            parser.error(f"Source differs from pinned manifest: {relative}")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    scratch = args.work_dir.resolve() / run_id
    evidence = ROOT / "evidence" / run_id
    evidence.mkdir(parents=True)
    scratch.mkdir(parents=True)
    env = os.environ.copy()
    # Avoid ambient JVM/Maven switches and injected settings.
    # JAVA_HOME is preserved and recorded.
    for key in (
        "MAVEN_ARGS",
        "MAVEN_OPTS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
    ):
        env.pop(key, None)
    env["LC_ALL"] = "C"
    mvn = shutil.which("mvn")
    if not mvn:
        parser.error("Maven is required on PATH")
    report: Report = {
        "run_id": run_id,
        "scratch": str(scratch),
        "source_commit": manifest["commit"],
        "scenarios": [],
    }
    report["source_sha256"] = {
        str(p.relative_to(ROOT / "source")): digest(p)
        for p in sorted((ROOT / "source").rglob("*"))
        if p.is_file()
    }
    version = subprocess.run(
        [mvn, "-version"], capture_output=True, text=True, env=env, timeout=30
    )
    (evidence / "toolchain.txt").write_text(version.stdout + version.stderr)
    report["toolchain"] = version.stdout + version.stderr

    for name, scenario in SCENARIOS.items():
        if args.scenario not in ("all", name):
            continue
        print(f"{name}: starting with an empty Maven cache", flush=True)
        result = run_scenario(
            name, scenario, scratch, evidence, env, mvn, args.settings
        )
        report["scenarios"].append(result)
        (evidence / "results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(f"{name}: {result['status']}", flush=True)
    (evidence / "REPORT.md").write_text(render_report(report))
    print(f"Evidence: {evidence}", flush=True)
    return 0 if all(r["status"] == "PASS" for r in report["scenarios"]) else 1


if __name__ == "__main__":
    sys.exit(main())

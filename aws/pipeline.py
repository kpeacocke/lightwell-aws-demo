#!/usr/bin/env python3
"""Run inside CodeBuild: publish, build, scan and execute the demo."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, overload
from xml.sax.saxutils import escape

import boto3
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_codeartifact.client import CodeArtifactClient
    from mypy_boto3_ecr.client import ECRClient
    from mypy_boto3_ecs.client import ECSClient
    from mypy_boto3_inspector2.client import Inspector2Client
    from mypy_boto3_logs.client import CloudWatchLogsClient

ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2022-40152"
PATCH = "6.0.3.rhlw-00001"
SCENARIOS = ("baseline", "conventional", "lightwell")
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"


@overload
def _aws_client(
    session: Any, service_name: Literal["codeartifact"]
) -> CodeArtifactClient: ...


@overload
def _aws_client(session: Any, service_name: Literal["ecs"]) -> ECSClient: ...


@overload
def _aws_client(session: Any, service_name: Literal["ecr"]) -> ECRClient: ...


@overload
def _aws_client(
    session: Any, service_name: Literal["inspector2"]
) -> Inspector2Client: ...


@overload
def _aws_client(
    session: Any, service_name: Literal["logs"]
) -> CloudWatchLogsClient: ...


def _aws_client(session: Any, service_name: str) -> Any:
    return session.client(service_name)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payment_ok(output: str) -> bool:
    return all(
        re.search(p, output)
        for p in (
            r"Transaction Id:\s*PX-1001",
            r"Amount:\s*129\.99 USD",
            r"Status:\s*APPROVED",
        )
    )


def enhanced_for_repository(config: Mapping[str, Any], repository: str) -> bool:
    return config.get("scanType") == "ENHANCED" and any(
        fnmatch.fnmatchcase(repository, f["filter"])
        for rule in config.get("rules", [])
        if rule.get("scanFrequency") in ("CONTINUOUS_SCAN", "SCAN_ON_PUSH")
        for f in rule.get("repositoryFilters", [])
    )


def maven_settings(endpoint: str) -> str:
    return f"""<settings>
  <servers><server><id>codeartifact</id><username>aws</username>
    <password>${{env.CODEARTIFACT_AUTH_TOKEN}}</password>
  </server></servers>
  <mirrors><mirror><id>codeartifact</id><mirrorOf>*</mirrorOf>
    <url>{escape(endpoint)}</url>
  </mirror></mirrors>
</settings>
"""


def command(
    args: Sequence[str], log: Path, cwd: Path = ROOT, timeout: int = 600
) -> str:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as stream:
        proc = subprocess.run(
            args, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout
        )
    if proc.returncode:
        raise RuntimeError(f"Command failed ({proc.returncode}); see {log.name}")
    return log.read_text()


def maven(settings: Path, cache: Path) -> list[str]:
    return [
        "mvn",
        "-B",
        "-ntp",
        "-s",
        str(settings),
        "-gs",
        str(ROOT / "config/empty-settings.xml"),
        f"-Dmaven.repo.local={cache}",
        "-Dstyle.color=never",
    ]


def prepare_codeartifact(
    client: CodeArtifactClient, work: Path, evidence: Path
) -> tuple[Path, str]:
    domain, repo = os.environ["CA_DOMAIN"], os.environ["CA_REPOSITORY"]
    endpoint = client.get_repository_endpoint(
        domain=domain, repository=repo, format="maven"
    )["repositoryEndpoint"]
    os.environ["CODEARTIFACT_AUTH_TOKEN"] = client.get_authorization_token(
        domain=domain, durationSeconds=3600
    )["authorizationToken"]
    settings = work / "codeartifact-settings.xml"
    settings.write_text(maven_settings(endpoint))
    seed = work / "seed"
    # Fetch exactly one patch from the vendor; do not mirror the vendor registry.
    command(
        maven(ROOT / "config/lightwell-settings.xml", seed)
        + [
            f"{DEPENDENCY_PLUGIN}:get",
            f"-Dartifact=com.fasterxml.woodstox:woodstox-core:{PATCH}",
            "-Dtransitive=false",
        ],
        evidence / "codeartifact-fetch.log",
        cwd=ROOT / "source",
    )
    directory = seed / "com/fasterxml/woodstox/woodstox-core" / PATCH
    jar = directory / f"woodstox-core-{PATCH}.jar"
    pom = directory / f"woodstox-core-{PATCH}.pom"
    client.put_package_origin_configuration(
        domain=domain,
        repository=repo,
        format="maven",
        namespace="com.fasterxml.woodstox",
        package="woodstox-core",
        restrictions={"publish": "ALLOW", "upstream": "ALLOW"},
    )
    existing = False
    try:
        remote_hashes: dict[str, str] = {}
        for asset in (jar, pom):
            remote = client.get_package_version_asset(
                domain=domain,
                repository=repo,
                format="maven",
                namespace="com.fasterxml.woodstox",
                package="woodstox-core",
                packageVersion=PATCH,
                asset=asset.name,
            )["asset"]
            try:
                remote_hashes[asset.name] = hashlib.sha256(remote.read()).hexdigest()
            finally:
                remote.close()
        if any(remote_hashes[asset.name] != sha(asset) for asset in (jar, pom)):
            raise RuntimeError("Existing CodeArtifact patch differs from vendor bytes")
        existing = True
    except ClientError as error:
        error_detail = error.response.get("Error")
        if (
            error_detail is None
            or error_detail.get("Code") != "ResourceNotFoundException"
        ):
            raise
    if not existing:
        command(
            maven(settings, work / "publisher-cache")
            + [
                "org.apache.maven.plugins:maven-deploy-plugin:3.1.3:deploy-file",
                f"-Dfile={jar}",
                f"-DpomFile={pom}",
                "-Dpackaging=jar",
                "-DrepositoryId=codeartifact",
                f"-Durl={endpoint}",
            ],
            evidence / "codeartifact-publish.log",
            cwd=ROOT / "source",
        )
    write_json(
        evidence / "codeartifact.json",
        {
            "mode": "Explicit publication, not a remote proxy",
            "repository": endpoint,
            "reused_identical_package": existing,
            "package": f"com.fasterxml.woodstox:woodstox-core:{PATCH}",
            "vendor_jar_sha256": sha(jar),
            "vendor_pom_sha256": sha(pom),
            "package_origin_restrictions": {"publish": "ALLOW", "upstream": "ALLOW"},
            "credential": "Environment reference only; token not retained",
        },
    )
    return settings, sha(jar)


def require_local_results(report: Mapping[str, Any]) -> None:
    expected = {"baseline", "pinned-failure", "conventional", "lightwell"}
    results: list[dict[str, Any]] = report.get("scenarios", [])
    if {r["name"] for r in results} != expected or len(results) != 4:
        raise RuntimeError("Missing or duplicate scenario results")
    if any(r.get("status") != "PASS" for r in results):
        raise RuntimeError("A local scenario did not meet its expected outcome")


def build_images(
    ecr: ECRClient,
    settings: Path,
    report: Mapping[str, Any],
    work: Path,
    evidence: Path,
    vendor_hash: str,
) -> dict[str, dict[str, str]]:
    authorization_data = ecr.get_authorization_token().get("authorizationData", [])
    if not authorization_data:
        raise RuntimeError("ECR did not return authorization data")
    login = authorization_data[0]
    token = login.get("authorizationToken")
    proxy_endpoint = login.get("proxyEndpoint")
    if token is None or proxy_endpoint is None:
        raise RuntimeError("ECR authorization data is incomplete")
    user, password = base64.b64decode(token).decode().split(":", 1)
    subprocess.run(
        [
            "docker",
            "login",
            "--username",
            user,
            "--password-stdin",
            proxy_endpoint,
        ],
        input=password,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Resolve the base once so all scenarios use identical base bytes.
    base = os.environ["RUNTIME_BASE"]
    command(
        ["docker", "pull", "--platform", "linux/amd64", base],
        evidence / "runtime-pull.log",
    )
    inspected = json.loads(
        subprocess.check_output(["docker", "image", "inspect", base])
    )[0]
    base_digest = inspected["RepoDigests"][0]
    write_json(
        evidence / "runtime-base.json",
        {
            "requested": base,
            "resolved": base_digest,
            "image_id": inspected["Id"],
        },
    )
    images: dict[str, dict[str, str]] = {}
    for scenario in SCENARIOS:
        project = Path(report["scratch"]) / scenario / "project"
        cache = project.parent / "m2"
        context = work / "containers" / scenario
        context.mkdir(parents=True)
        command(
            maven(settings, cache)
            + [
                f"{DEPENDENCY_PLUGIN}:copy-dependencies",
                "-DincludeScope=runtime",
                f"-DoutputDirectory={context / 'lib'}",
            ],
            evidence / f"{scenario}-copy-runtime.log",
            cwd=project,
        )
        command(
            maven(settings, cache)
            + ["org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom"],
            evidence / f"{scenario}-sbom.log",
            cwd=project,
        )
        shutil.copyfile(project / "target/bom.json", evidence / f"{scenario}-sbom.json")
        shutil.copyfile(
            project / "target/paymentgateway-1.0.0.jar", context / "app.jar"
        )
        shutil.copyfile(ROOT / "aws/Dockerfile", context / "Dockerfile")
        inventory = {p.name: sha(p) for p in sorted((context / "lib").glob("*.jar"))}
        if scenario == "lightwell":
            if inventory.get(f"woodstox-core-{PATCH}.jar") != vendor_hash:
                raise RuntimeError(
                    "CodeArtifact-resolved patch differs from vendor bytes"
                )
        write_json(evidence / f"{scenario}-runtime-inventory.json", inventory)
        tag = f"{report['run_id'].lower()}-{scenario}"
        uri = f"{os.environ['ECR_URI']}:{tag}"
        command(
            [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--build-arg",
                f"RUNTIME_BASE={base_digest}",
                "-t",
                uri,
                str(context),
            ],
            evidence / f"{scenario}-image-build.log",
        )
        output = command(
            ["docker", "run", "--rm", "--network", "none", "--read-only", uri],
            evidence / f"{scenario}-container.log",
        )
        if not payment_ok(output):
            raise RuntimeError(f"{scenario}: container payment output mismatch")
        command(["docker", "push", uri], evidence / f"{scenario}-push.log")
        image_details = ecr.describe_images(
            repositoryName=os.environ["ECR_REPOSITORY"], imageIds=[{"imageTag": tag}]
        ).get("imageDetails", [])
        if not image_details:
            raise RuntimeError(f"{scenario}: ECR did not return an image digest")
        digest = image_details[0].get("imageDigest")
        if digest is None:
            raise RuntimeError(f"{scenario}: ECR did not return an image digest")
        images[scenario] = {
            "tag": tag,
            "digest": digest,
            "uri": f"{os.environ['ECR_URI']}@{digest}",
        }
        write_json(evidence / "images.json", images)
    return images


def run_fargate(
    ecs: ECSClient,
    logs: CloudWatchLogsClient,
    image: Mapping[str, str],
    scenario: str,
    evidence: Path,
) -> dict[str, str]:
    family = os.environ["DEMO_NAME"] + "-runtime"
    registration = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=os.environ["TASK_EXECUTION_ROLE"],
        runtimePlatform={"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"},
        containerDefinitions=[
            {
                "name": "payment",
                "image": image["uri"],
                "essential": True,
                "readonlyRootFilesystem": True,
                "user": "10001",
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": os.environ["TASK_LOG_GROUP"],
                        "awslogs-region": os.environ["AWS_DEFAULT_REGION"],
                        "awslogs-stream-prefix": "demo",
                    },
                },
            }
        ],
    )
    definition = registration["taskDefinition"].get("taskDefinitionArn")
    if definition is None:
        raise RuntimeError("ECS did not return a task definition ARN")
    task_arn = None
    task = None
    stopped = False
    try:
        response = ecs.run_task(
            cluster=os.environ["ECS_CLUSTER"],
            taskDefinition=definition,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [os.environ["TASK_SUBNET"]],
                    "securityGroups": [os.environ["TASK_SECURITY_GROUP"]],
                    "assignPublicIp": "DISABLED",
                }
            },
        )
        write_json(evidence / f"{scenario}-task-start.json", response)
        if response.get("failures") or len(response.get("tasks", [])) != 1:
            raise RuntimeError("Fargate rejected the task launch")
        tasks = response.get("tasks", [])
        if not tasks:
            raise RuntimeError("ECS did not return a task ARN")
        task_arn = tasks[0].get("taskArn")
        if task_arn is None:
            raise RuntimeError("ECS did not return a task ARN")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            details = ecs.describe_tasks(
                cluster=os.environ["ECS_CLUSTER"], tasks=[task_arn]
            )
            write_json(evidence / f"{scenario}-task.json", details)
            if details.get("failures"):
                raise RuntimeError("Cannot describe Fargate task")
            task = details["tasks"][0]
            if task.get("lastStatus") == "STOPPED":
                stopped = True
                break
            time.sleep(5)
        if not stopped:
            raise RuntimeError("Fargate task exceeded five-minute deadline")
        if task is None:
            raise RuntimeError("Fargate stopped without returning task details")
        containers = task.get("containers", [])
        if len(containers) != 1 or containers[0].get("exitCode") != 0:
            raise RuntimeError(f"Fargate failed: {task.get('stoppedReason')}")
        stream = "demo/payment/" + task_arn.rsplit("/", 1)[1]
        output = ""
        for _ in range(12):
            try:
                events = logs.get_log_events(
                    logGroupName=os.environ["TASK_LOG_GROUP"],
                    logStreamName=stream,
                    startFromHead=True,
                )
                output = "\n".join(
                    event.get("message") or "" for event in events.get("events", [])
                )
            except logs.exceptions.ResourceNotFoundException:
                output = ""
            if payment_ok(output):
                break
            time.sleep(5)
        (evidence / f"{scenario}-fargate-output.log").write_text(output)
        if not payment_ok(output):
            raise RuntimeError(
                "Fargate output missing or did not match expected payment"
            )
        return {"status": "PASS", "task_arn": task_arn, "image": image["uri"]}
    finally:
        if task_arn and not stopped:
            ecs.stop_task(
                cluster=os.environ["ECS_CLUSTER"],
                task=task_arn,
                reason="Demo timeout or error cleanup",
            )
        ecs.deregister_task_definition(taskDefinition=definition)


def scan_images(
    ecr: ECRClient,
    images: Mapping[str, Mapping[str, str]],
    evidence: Path,
    timeout: int = 600,
) -> dict[str, dict[str, Any]]:
    pending = dict(images)
    results: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for name, image in list(pending.items()):
            try:
                pages: list[Mapping[str, Any]] = []
                token: str | None = None
                while True:
                    args: dict[str, Any] = {
                        "repositoryName": os.environ["ECR_REPOSITORY"],
                        "imageId": {"imageDigest": image["digest"]},
                        "maxResults": 1000,
                    }
                    if token:
                        args["nextToken"] = token
                    page = ecr.describe_image_scan_findings(**args)
                    pages.append(page)
                    token = page.get("nextToken")
                    if not token:
                        break
                write_json(evidence / f"{name}-inspector.json", pages)
                state = pages[0].get("imageScanStatus", {}).get("status")
                scanned = (
                    pages[0].get("imageScanFindings", {}).get("imageScanCompletedAt")
                )
                if state in ("FAILED", "UNSUPPORTED_IMAGE", "SCAN_ELIGIBILITY_EXPIRED"):
                    raise RuntimeError(f"{name}: image scan cannot complete: {state}")
                # ACTIVE means continuous coverage, not by itself a completed scan.
                if state not in ("ACTIVE", "COMPLETE") or not scanned:
                    continue
                findings: list[Mapping[str, Any]] = [
                    f
                    for p in pages
                    for f in p.get("imageScanFindings", {}).get("enhancedFindings", [])
                ]
                matching = [
                    f
                    for f in findings
                    if f.get("packageVulnerabilityDetails", {}).get("vulnerabilityId")
                    == CVE
                ]
                results[name] = {
                    "scan_status": state,
                    "scan_completed_at": scanned,
                    "target_cve": CVE,
                    "target_findings": matching,
                    "interpretation": "REPORTED" if matching else "NOT_REPORTED",
                    "backport_recognition": "NOT_ESTABLISHED",
                    "note": (
                        "No finding is not proof of patch recognition "
                        "or package coverage."
                    ),
                }
                del pending[name]
            except ClientError as error:
                error_detail = error.response.get("Error")
                if error_detail is None or error_detail.get("Code") not in (
                    "ScanNotFoundException",
                    "ImageNotFoundException",
                ):
                    raise
        if pending:
            time.sleep(10)
    for name in pending:
        results[name] = {
            "interpretation": "INCONCLUSIVE",
            "reason": "Scan deadline exceeded",
        }
    write_json(evidence / "scan-comparison.json", results)
    if pending:
        raise RuntimeError("Inspector scan incomplete; see scan-comparison.json")
    return results


def main() -> int:
    work = Path("/tmp/lightwell-aws")
    work.mkdir(exist_ok=True)
    evidence = ROOT / "evidence/aws"
    evidence.mkdir(parents=True, exist_ok=True)
    session = boto3.Session()
    ecr = _aws_client(session, "ecr")
    summary: dict[str, Any] = {
        "status": "RUNNING",
        "stages": {},
        "security_fix_verified": False,
    }
    try:
        scan_mode = os.environ.get("INSPECTOR_SCAN_MODE", "required")
        if scan_mode not in ("required", "skip"):
            raise RuntimeError(f"Invalid INSPECTOR_SCAN_MODE: {scan_mode}")
        if scan_mode == "required":
            config = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
            write_json(evidence / "registry-scanning.json", config)
            if not enhanced_for_repository(config, os.environ["ECR_REPOSITORY"]):
                raise RuntimeError(
                    "Enable Inspector ECR enhanced scanning for this repository first"
                )
        else:
            summary["stages"]["inspector"] = "SKIPPED"
            print("Inspector scanning skipped; no scan evidence will be collected.")
        settings, vendor_hash = prepare_codeartifact(
            _aws_client(session, "codeartifact"), work, evidence
        )
        summary["stages"]["codeartifact"] = "PUBLISHED"
        command(
            [
                sys.executable,
                str(ROOT / "run_scenarios.py"),
                "--work-dir",
                str(work / "scenarios"),
                "--settings",
                str(settings),
            ],
            evidence / "scenario-runner.log",
            timeout=2400,
        )
        result_files = list((ROOT / "evidence").glob("*/results.json"))
        if len(result_files) != 1:
            raise RuntimeError("Source archive must not contain earlier evidence")
        report = json.loads(result_files[0].read_text())
        require_local_results(report)
        summary["stages"]["scenarios"] = "PASS"
        images = build_images(ecr, settings, report, work, evidence, vendor_hash)
        summary["images"] = images
        summary["stages"]["images"] = "PASS"
        summary["tasks"] = {}
        for scenario in ("conventional", "lightwell"):
            summary["tasks"][scenario] = run_fargate(
                _aws_client(session, "ecs"),
                _aws_client(session, "logs"),
                images[scenario],
                scenario,
                evidence,
            )
        summary["stages"]["fargate"] = "PASS"
        if scan_mode == "skip":
            summary["scans"] = {
                name: {
                    "interpretation": "SKIPPED",
                    "reason": "Inspector scanning explicitly skipped",
                    "backport_recognition": "NOT_ESTABLISHED",
                }
                for name in images
            }
            write_json(evidence / "scan-comparison.json", summary["scans"])
            summary["status"] = "INTEGRATION_PASS_INSPECTOR_SKIPPED"
        else:
            # Separate resource coverage from findings. Preserve both raw responses.
            coverage = list(
                _aws_client(session, "inspector2")
                .get_paginator("list_coverage")
                .paginate(
                    filterCriteria={
                        "ecrRepositoryName": [
                            {
                                "comparison": "EQUALS",
                                "value": os.environ["ECR_REPOSITORY"],
                            }
                        ]
                    },
                )
            )
            write_json(evidence / "inspector-coverage.json", coverage)
            summary["scans"] = scan_images(ecr, images, evidence)
            summary["status"] = "INTEGRATION_PASS_SECURITY_REVIEW_REQUIRED"
        return 0
    except Exception as error:
        summary["status"] = "FAILED"
        summary["error"] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        write_json(evidence / "integration.json", summary)
        print("Evidence: evidence/aws/integration.json", flush=True)


if __name__ == "__main__":
    sys.exit(main())

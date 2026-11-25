#!/usr/bin/env python3
"""Package, deploy and operate the Lightwell AWS demo with an explicit profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, overload

import boto3
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudformation.client import CloudFormationClient
    from mypy_boto3_cloudformation.type_defs import (
        CreateStackInputTypeDef,
        ParameterTypeDef,
        UpdateStackInputTypeDef,
    )
    from mypy_boto3_codebuild.client import CodeBuildClient
    from mypy_boto3_codebuild.type_defs import StartBuildInputTypeDef
    from mypy_boto3_ecr.client import ECRClient
    from mypy_boto3_ecs.client import ECSClient
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_s3.type_defs import ObjectIdentifierTypeDef
    from mypy_boto3_sts.client import STSClient

ROOT = Path(__file__).resolve().parents[1]


class DemoArguments(argparse.Namespace):
    action: str
    profile: str | None
    region: str | None
    stack: str
    runtime_base: str
    output: Path
    build_id: str | None
    wait: bool
    allow_demo_artifact_publication: bool
    skip_inspector: bool


@overload
def _aws_client(
    session: Any, service_name: Literal["cloudformation"]
) -> CloudFormationClient: ...


@overload
def _aws_client(
    session: Any, service_name: Literal["codebuild"]
) -> CodeBuildClient: ...


@overload
def _aws_client(session: Any, service_name: Literal["ecs"]) -> ECSClient: ...


@overload
def _aws_client(session: Any, service_name: Literal["ecr"]) -> ECRClient: ...


@overload
def _aws_client(session: Any, service_name: Literal["s3"]) -> S3Client: ...


@overload
def _aws_client(session: Any, service_name: Literal["sts"]) -> STSClient: ...


def _aws_client(session: Any, service_name: str) -> Any:
    return session.client(service_name)


def package(destination: Path) -> str:
    """Allowlist source files; never upload local evidence, settings or credentials."""
    names = [
        "run_scenarios.py",
        "SOURCE-MANIFEST.json",
        "config/empty-settings.xml",
        "config/lightwell-settings.xml",
        "aws/pipeline.py",
        "aws/Dockerfile",
        "aws/buildspec.yml",
        "aws/requirements.txt",
    ]
    manifest = json.loads((ROOT / "SOURCE-MANIFEST.json").read_text())
    for path, expected in manifest["sha256"].items():
        source = ROOT / "source" / path
        if (
            source.is_symlink()
            or hashlib.sha256(source.read_bytes()).hexdigest() != expected
        ):
            raise RuntimeError(f"Source manifest mismatch: {path}")
        names.append("source/" + path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(names):
            path = ROOT / name
            if path.is_symlink():
                raise RuntimeError(f"Refusing symlink in source package: {name}")
            archive.write(path, name)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def outputs(cf: CloudFormationClient, stack: str) -> dict[str, str]:
    stacks = cf.describe_stacks(StackName=stack).get("Stacks", [])
    if not stacks:
        raise RuntimeError(f"Stack not found: {stack}")
    details = stacks[0]
    status = details.get("StackStatus")
    if status not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise RuntimeError(f"Stack not ready: {status}")
    stack_outputs = details.get("Outputs")
    if stack_outputs is None:
        raise RuntimeError(f"Stack has no outputs: {stack}")
    result: dict[str, str] = {}
    for output in stack_outputs:
        key = output.get("OutputKey")
        value = output.get("OutputValue")
        if key is None or value is None:
            raise RuntimeError(f"Stack output is incomplete: {stack}")
        result[key] = value
    return result


def deploy(session: boto3.Session, args: DemoArguments) -> None:
    cf = _aws_client(session, "cloudformation")
    template = (ROOT / "aws/template.yaml").read_text()
    parameters: list[ParameterTypeDef] = [
        {"ParameterKey": "DemoName", "ParameterValue": args.stack},
        {"ParameterKey": "RuntimeBase", "ParameterValue": args.runtime_base},
    ]
    create_request: CreateStackInputTypeDef = {
        "StackName": args.stack,
        "TemplateBody": template,
        "Parameters": parameters,
        "Capabilities": ["CAPABILITY_IAM"],
    }
    update_request: UpdateStackInputTypeDef = {
        "StackName": args.stack,
        "TemplateBody": template,
        "Parameters": parameters,
        "Capabilities": ["CAPABILITY_IAM"],
    }
    try:
        cf.describe_stacks(StackName=args.stack)
    except ClientError as error:
        error_detail = error.response.get("Error")
        if (
            error_detail is None
            or error_detail.get("Code") != "ValidationError"
            or "does not exist" not in str(error)
        ):
            raise
        cf.create_stack(**create_request)
        waiter = cf.get_waiter("stack_create_complete")
    else:
        try:
            cf.update_stack(**update_request)
        except ClientError as error:
            if "No updates are to be performed" not in str(error):
                raise
            print(json.dumps(outputs(cf, args.stack), indent=2))
            return
        waiter = cf.get_waiter("stack_update_complete")
    print(
        "Waiting for CloudFormation; inspect stack events if provisioning fails.",
        flush=True,
    )
    waiter.wait(StackName=args.stack)
    print(json.dumps(outputs(cf, args.stack), indent=2))


def enable_scanning(session: boto3.Session, state: Mapping[str, str]) -> None:
    """Explicit operator action; preserve existing rules and save rollback evidence."""
    ecr = _aws_client(session, "ecr")
    prior = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    # Import locally so packaging and deploy do not import pipeline dependencies twice.
    from pipeline import enhanced_for_repository

    if enhanced_for_repository(prior, state["Repository"]):
        print("Enhanced scanning already covers the demo repository.")
        return
    if prior.get("scanType") != "ENHANCED":
        raise RuntimeError(
            "Enable Amazon Inspector ECR scanning in this account first. "
            "This command will not convert a shared BASIC registry."
        )
    rules = prior.get("rules", [])
    if len(rules) >= 2:
        raise RuntimeError(
            "Registry already has two rules; add the demo repository "
            "filter to an existing rule in ECR settings."
        )
    key = "setup/registry-scanning-before-demo.json"
    s3 = _aws_client(session, "s3")
    try:
        s3.put_object(
            Bucket=state["Bucket"],
            Key=key,
            Body=json.dumps(prior).encode(),
            IfNoneMatch="*",
        )
    except ClientError as error:
        error_detail = error.response.get("Error")
        if error_detail is None or error_detail.get("Code") not in (
            "PreconditionFailed",
            "412",
        ):
            raise
        raise RuntimeError(
            "A prior scanning snapshot exists; review it before changing rules"
        ) from error
    rules.append(
        {
            "scanFrequency": "CONTINUOUS_SCAN",
            "repositoryFilters": [
                {"filter": state["Repository"], "filterType": "WILDCARD"}
            ],
        }
    )
    ecr.put_registry_scanning_configuration(scanType="ENHANCED", rules=rules)
    print(f"Added demo scan rule; previous configuration: s3://{state['Bucket']}/{key}")


def start_build(
    session: boto3.Session, state: Mapping[str, str], args: DemoArguments
) -> None:
    if not args.allow_demo_artifact_publication:
        raise RuntimeError(
            "Run requires --allow-demo-artifact-publication: confirm "
            "you may publish this Red Hat demo patch to your account."
        )
    from pipeline import enhanced_for_repository

    if not args.skip_inspector:
        ecr = _aws_client(session, "ecr")
        config = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
        if not enhanced_for_repository(config, state["Repository"]):
            raise RuntimeError(
                "Inspector enhanced scanning does not cover this repository"
            )
    else:
        print(
            "Inspector scanning explicitly skipped; no scan evidence will be collected."
        )
    archive = ROOT / ".aws-demo/source.zip"
    checksum = package(archive)
    key = f"source/{checksum}.zip"
    _aws_client(session, "s3").upload_file(str(archive), state["Bucket"], key)
    request: StartBuildInputTypeDef = {
        "projectName": state["Project"],
        "sourceLocationOverride": f"{state['Bucket']}/{key}",
    }
    if args.skip_inspector:
        request["environmentVariablesOverride"] = [
            {"name": "INSPECTOR_SCAN_MODE", "value": "skip", "type": "PLAINTEXT"}
        ]
    build = _aws_client(session, "codebuild").start_build(**request).get("build")
    build_id = build.get("id")
    if build_id is None:
        raise RuntimeError("CodeBuild did not return a build ID")
    print(json.dumps({"build_id": build_id, "source_sha256": checksum}, indent=2))
    if args.wait:
        monitor(session, build_id)


def monitor(session: boto3.Session, build_id: str) -> None:
    client = _aws_client(session, "codebuild")
    while True:
        response = client.batch_get_builds(ids=[build_id])
        if not response["builds"]:
            raise RuntimeError("Build not found")
        build = response["builds"][0]
        status = build.get("buildStatus")
        if status is None:
            raise RuntimeError("CodeBuild response did not include a build status")
        print(f"{status}: {build.get('currentPhase', '')}", flush=True)
        if status != "IN_PROGRESS":
            print(
                json.dumps(
                    {"logs": build.get("logs"), "artifacts": build.get("artifacts")},
                    indent=2,
                )
            )
            if status != "SUCCEEDED":
                raise RuntimeError("Build did not succeed; inspect logs and evidence")
            return
        time.sleep(15)


def delete_access_log_bucket(s3: S3Client, bucket: str) -> None:
    objects: list[ObjectIdentifierTypeDef] = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        items: list[Mapping[str, Any]] = [
            *page.get("Versions", []),
            *page.get("DeleteMarkers", []),
        ]
        for item in items:
            key, version = item.get("Key"), item.get("VersionId")
            if key is None or version is None or not key.startswith("access/"):
                raise RuntimeError(
                    f"Unexpected object in access-log bucket {bucket}; review it "
                    "before deleting the bucket"
                )
            objects.append({"Key": key, "VersionId": version})
    for offset in range(0, len(objects), 1000):
        result = s3.delete_objects(
            Bucket=bucket, Delete={"Objects": objects[offset : offset + 1000]}
        )
        if result.get("Errors"):
            raise RuntimeError(
                f"Could not delete access logs from bucket {bucket}: {result['Errors']}"
            )
    s3.delete_bucket(Bucket=bucket)


def cleanup(session: boto3.Session, state: Mapping[str, str], stack: str) -> None:
    builds = _aws_client(session, "codebuild")
    ids = builds.list_builds_for_project(projectName=state["Project"])["ids"]
    for offset in range(0, len(ids), 100):
        for build in builds.batch_get_builds(ids=ids[offset : offset + 100])["builds"]:
            if build.get("buildStatus") == "IN_PROGRESS":
                raise RuntimeError("Stop/wait for active builds before cleanup")
    ecs = _aws_client(session, "ecs")
    for page in ecs.get_paginator("list_tasks").paginate(cluster=state["Cluster"]):
        for task in page["taskArns"]:
            ecs.stop_task(cluster=state["Cluster"], task=task, reason="Demo cleanup")
            ecs.get_waiter("tasks_stopped").wait(cluster=state["Cluster"], tasks=[task])
    for page in ecs.get_paginator("list_task_definitions").paginate(
        familyPrefix=stack + "-runtime", status="ACTIVE"
    ):
        for arn in page["taskDefinitionArns"]:
            if arn.rsplit("/", 1)[1].split(":")[0] == stack + "-runtime":
                ecs.deregister_task_definition(taskDefinition=arn)
    # Remove only the exact rule created by enable-scanning, retaining later changes.
    ecr = _aws_client(session, "ecr")
    s3 = _aws_client(session, "s3")
    try:
        s3.head_object(
            Bucket=state["Bucket"], Key="setup/registry-scanning-before-demo.json"
        )
    except ClientError as error:
        error_detail = error.response.get("Error")
        if error_detail is None or error_detail.get("Code") not in ("404", "NoSuchKey"):
            raise
    else:
        current = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
        owned: dict[str, Any] = {
            "scanFrequency": "CONTINUOUS_SCAN",
            "repositoryFilters": [
                {"filter": state["Repository"], "filterType": "WILDCARD"}
            ],
        }
        scan_type = current.get("scanType")
        if scan_type is None:
            raise RuntimeError("ECR scanning configuration has no scan type")
        rules = current.get("rules", [])
        if owned in rules:
            rules = [rule for rule in rules if rule != owned]
            ecr.put_registry_scanning_configuration(scanType=scan_type, rules=rules)
    log_bucket = state.get("AccessLogBucket")
    if log_bucket:
        if log_bucket == state["Bucket"]:
            raise RuntimeError("Access-log and evidence buckets must be distinct")
        logging = s3.get_bucket_logging(Bucket=state["Bucket"]).get("LoggingEnabled")
        if logging:
            if (
                logging.get("TargetBucket") != log_bucket
                or logging.get("TargetPrefix") != "access/"
            ):
                raise RuntimeError(
                    f"Evidence bucket logging does not match {log_bucket}/access/"
                )
            s3.put_bucket_logging(Bucket=state["Bucket"], BucketLoggingStatus={})
    cf = _aws_client(session, "cloudformation")
    cf.delete_stack(StackName=stack)
    cf.get_waiter("stack_delete_complete").wait(StackName=stack)
    if log_bucket:
        try:
            delete_access_log_bucket(s3, log_bucket)
        except (ClientError, RuntimeError) as error:
            raise RuntimeError(
                f"Stack deleted, but access-log bucket {log_bucket} remains; "
                f"review and remove it manually: {error}"
            ) from error
        print(f"Deleted access-log bucket: {log_bucket}")
    print(f"Deleted demo stack. Evidence bucket retained: {state['Bucket']}")
    print(
        "Inspector remains enabled. Evidence current objects expire after 30 days; "
        "noncurrent versions expire later."
    )


def main() -> int | None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=["package", "deploy", "enable-scanning", "run", "status", "cleanup"],
    )
    parser.add_argument("--profile")
    parser.add_argument("--region")
    parser.add_argument("--stack", default="lightwell-demo")
    parser.add_argument(
        "--runtime-base", default="public.ecr.aws/amazoncorretto/amazoncorretto:11"
    )
    parser.add_argument("--output", type=Path, default=ROOT / ".aws-demo/source.zip")
    parser.add_argument("--build-id")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--allow-demo-artifact-publication", action="store_true")
    parser.add_argument(
        "--skip-inspector",
        action="store_true",
        help="Run without Inspector scan evidence (run action only)",
    )
    args = parser.parse_args(namespace=DemoArguments())
    if args.skip_inspector and args.action != "run":
        parser.error("--skip-inspector is only valid for run")
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,30}", args.stack):
        parser.error("Stack name must be 3-31 lowercase letters, digits or hyphens")
    if args.action == "package":
        print(f"{args.output}: sha256 {package(args.output)}")
        return 0
    if not args.region:
        parser.error("--region is required for AWS actions")
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account = _aws_client(session, "sts").get_caller_identity()["Account"]
    print(
        f"AWS account {account}; Region {args.region}; stack {args.stack}", flush=True
    )
    if args.action == "deploy":
        deploy(session, args)
    elif args.action == "status":
        if not args.build_id:
            parser.error("--build-id is required")
        monitor(session, args.build_id)
    else:
        state = outputs(_aws_client(session, "cloudformation"), args.stack)
        if args.action == "enable-scanning":
            enable_scanning(session, state)
        elif args.action == "run":
            start_build(session, state, args)
        else:
            cleanup(session, state, args.stack)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ClientError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

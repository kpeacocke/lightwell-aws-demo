#!/usr/bin/env python3
"""Package, deploy and operate the Lightwell AWS demo with an explicit profile."""

import argparse
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]


def package(destination):
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


def outputs(cf, stack):
    details = cf.describe_stacks(StackName=stack)["Stacks"][0]
    if details["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
        raise RuntimeError(f"Stack not ready: {details['StackStatus']}")
    return {v["OutputKey"]: v["OutputValue"] for v in details["Outputs"]}


def deploy(session, args):
    cf = session.client("cloudformation")
    template = (ROOT / "aws/template.yaml").read_text()
    parameters = [
        {"ParameterKey": "DemoName", "ParameterValue": args.stack},
        {"ParameterKey": "RuntimeBase", "ParameterValue": args.runtime_base},
    ]
    request = dict(
        StackName=args.stack,
        TemplateBody=template,
        Parameters=parameters,
        Capabilities=["CAPABILITY_IAM"],
    )
    try:
        cf.describe_stacks(StackName=args.stack)
    except ClientError as error:
        if error.response["Error"][
            "Code"
        ] != "ValidationError" or "does not exist" not in str(error):
            raise
        cf.create_stack(**request)
        waiter = cf.get_waiter("stack_create_complete")
    else:
        try:
            cf.update_stack(**request)
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


def enable_scanning(session, state):
    """Explicit operator action; preserve existing rules and save rollback evidence."""
    ecr = session.client("ecr")
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
    s3 = session.client("s3")
    try:
        s3.put_object(
            Bucket=state["Bucket"],
            Key=key,
            Body=json.dumps(prior).encode(),
            IfNoneMatch="*",
        )
    except ClientError as error:
        if error.response["Error"]["Code"] not in ("PreconditionFailed", "412"):
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


def start_build(session, state, args):
    if not args.allow_demo_artifact_publication:
        raise RuntimeError(
            "Run requires --allow-demo-artifact-publication: confirm "
            "you may publish this Red Hat demo patch to your account."
        )
    from pipeline import enhanced_for_repository

    if not args.skip_inspector:
        ecr = session.client("ecr")
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
    session.client("s3").upload_file(str(archive), state["Bucket"], key)
    request: dict[str, str | list[dict[str, str]]] = {
        "projectName": state["Project"],
        "sourceLocationOverride": f"{state['Bucket']}/{key}",
    }
    if args.skip_inspector:
        request["environmentVariablesOverride"] = [
            {"name": "INSPECTOR_SCAN_MODE", "value": "skip", "type": "PLAINTEXT"}
        ]
    build = session.client("codebuild").start_build(**request)["build"]
    print(json.dumps({"build_id": build["id"], "source_sha256": checksum}, indent=2))
    if args.wait:
        monitor(session, build["id"])


def monitor(session, build_id):
    client = session.client("codebuild")
    while True:
        response = client.batch_get_builds(ids=[build_id])
        if not response["builds"]:
            raise RuntimeError("Build not found")
        build = response["builds"][0]
        status = build["buildStatus"]
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


def cleanup(session, state, stack):
    builds = session.client("codebuild")
    ids = builds.list_builds_for_project(projectName=state["Project"])["ids"]
    for offset in range(0, len(ids), 100):
        for build in builds.batch_get_builds(ids=ids[offset : offset + 100])["builds"]:
            if build["buildStatus"] == "IN_PROGRESS":
                raise RuntimeError("Stop/wait for active builds before cleanup")
    ecs = session.client("ecs")
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
    ecr = session.client("ecr")
    s3 = session.client("s3")
    try:
        s3.head_object(
            Bucket=state["Bucket"], Key="setup/registry-scanning-before-demo.json"
        )
    except ClientError as error:
        if error.response["Error"]["Code"] not in ("404", "NoSuchKey"):
            raise
    else:
        current = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
        owned = {
            "scanFrequency": "CONTINUOUS_SCAN",
            "repositoryFilters": [
                {"filter": state["Repository"], "filterType": "WILDCARD"}
            ],
        }
        if owned in current.get("rules", []):
            rules = [rule for rule in current["rules"] if rule != owned]
            ecr.put_registry_scanning_configuration(
                scanType=current["scanType"], rules=rules
            )
    cf = session.client("cloudformation")
    cf.delete_stack(StackName=stack)
    cf.get_waiter("stack_delete_complete").wait(StackName=stack)
    print(f"Deleted demo stack. Evidence bucket retained: {state['Bucket']}")
    print("Inspector remains enabled. Evidence objects expire after 30 days.")


def main():
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
    args = parser.parse_args()
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
    account = session.client("sts").get_caller_identity()["Account"]
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
        state = outputs(session.client("cloudformation"), args.stack)
        if args.action == "enable-scanning":
            enable_scanning(session, state)
        elif args.action == "run":
            start_build(session, state, args)
        else:
            cleanup(session, state, args.stack)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ClientError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

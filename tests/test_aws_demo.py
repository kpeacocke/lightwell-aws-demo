"""Offline checks of failure handling and source/evidence boundaries."""

import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import Mock, patch

import boto3
from botocore.stub import Stubber

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load("pipeline", ROOT / "aws/pipeline.py")
cli = load("demo", ROOT / "aws/demo.py")


class DemoTests(unittest.TestCase):
    def test_explicit_profile_uses_environment_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            command = (
                f"{shlex.quote(sys.executable)} "
                f"{shlex.quote(str(ROOT / '.devcontainer/aws-credentials.py'))}"
            )
            config.write_text(
                f"[profile custom-demo]\ncredential_process = {command}\n"
            )
            env = {
                "AWS_CONFIG_FILE": str(config),
                "AWS_SHARED_CREDENTIALS_FILE": str(Path(directory) / "credentials"),
                "AWS_ACCESS_KEY_ID": "test-key",
                "AWS_SECRET_ACCESS_KEY": "test-secret",
                "AWS_SESSION_TOKEN": "test-token",
                "AWS_PROFILE": "custom-demo",
            }
            with patch.dict(os.environ, env, clear=True):
                credentials = boto3.Session(
                    profile_name="custom-demo", region_name="us-east-1"
                ).get_credentials()
                self.assertEqual(credentials.method, "custom-process")
                self.assertEqual(credentials.access_key, "test-key")
                self.assertEqual(credentials.secret_key, "test-secret")
                self.assertEqual(credentials.token, "test-token")
                self.assertEqual(boto3.Session().profile_name, "custom-demo")

    def test_profile_credential_process_rejects_missing_credentials(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / ".devcontainer/aws-credentials.py")],
            env={},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AWS_ACCESS_KEY_ID", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_source_archive_excludes_evidence_and_local_config(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "source.zip"
            cli.package(target)
            with zipfile.ZipFile(target) as archive:
                names = archive.namelist()
            self.assertIn("aws/pipeline.py", names)
            self.assertIn("source/pom_3_lightwell.xml", names)
            self.assertFalse(
                any(n.startswith(("evidence/", ".git/", ".vscode/")) for n in names)
            )
            self.assertNotIn("config/codeartifact-settings.xml", names)

    def test_manifest_change_prevents_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/pom.xml").write_text("changed")
            (root / "SOURCE-MANIFEST.json").write_text(
                json.dumps({"sha256": {"pom.xml": "not-the-hash"}})
            )
            with patch.object(cli, "ROOT", root), self.assertRaises(RuntimeError):
                cli.package(root / "out.zip")

    def test_settings_use_environment_token_and_cover_all_repositories(self):
        xml = pipeline.maven_settings("https://example.test/maven/demo/")
        self.assertIn("${env.CODEARTIFACT_AUTH_TOKEN}", xml)
        self.assertIn("<mirrorOf>*</mirrorOf>", xml)
        self.assertNotIn(os.environ.get("SECRET_TEST_TOKEN", "not-a-real-token"), xml)

    def test_basic_scanning_is_not_inspector(self):
        config = {
            "scanType": "BASIC",
            "rules": [
                {
                    "scanFrequency": "SCAN_ON_PUSH",
                    "repositoryFilters": [{"filter": "*"}],
                }
            ],
        }
        self.assertFalse(pipeline.enhanced_for_repository(config, "demo"))
        config["scanType"] = "ENHANCED"
        self.assertTrue(pipeline.enhanced_for_repository(config, "demo"))
        config["rules"][0]["repositoryFilters"][0]["filter"] = "other-*"
        self.assertFalse(pipeline.enhanced_for_repository(config, "demo"))

    def test_build_requires_inspector_unless_explicitly_skipped(self):
        state = {"Repository": "demo", "Bucket": "bucket", "Project": "project"}
        session = Mock()
        ecr, s3, codebuild = Mock(), Mock(), Mock()
        session.client.side_effect = {"ecr": ecr, "s3": s3, "codebuild": codebuild}.get
        ecr.get_registry_scanning_configuration.return_value = {
            "scanningConfiguration": {"scanType": "BASIC"}
        }
        codebuild.start_build.return_value = {"build": {"id": "build-id"}}
        args = Namespace(
            allow_demo_artifact_publication=True, skip_inspector=False, wait=False
        )
        with patch.dict(sys.modules, {"pipeline": pipeline}):
            args.allow_demo_artifact_publication = False
            args.skip_inspector = True
            with self.assertRaisesRegex(RuntimeError, "artifact-publication"):
                cli.start_build(session, state, args)
            args.allow_demo_artifact_publication = True
            args.skip_inspector = False
            with self.assertRaisesRegex(RuntimeError, "Inspector enhanced scanning"):
                cli.start_build(session, state, args)
            codebuild.start_build.assert_not_called()
            ecr.get_registry_scanning_configuration.return_value = {
                "scanningConfiguration": {
                    "scanType": "ENHANCED",
                    "rules": [
                        {
                            "scanFrequency": "SCAN_ON_PUSH",
                            "repositoryFilters": [{"filter": "demo"}],
                        }
                    ],
                }
            }
            with patch.object(cli, "package", return_value="checksum"):
                cli.start_build(session, state, args)
            self.assertNotIn(
                "environmentVariablesOverride", codebuild.start_build.call_args.kwargs
            )
            codebuild.start_build.reset_mock()
            s3.upload_file.reset_mock()
            args.skip_inspector = True
            with patch.object(cli, "package", return_value="checksum"):
                cli.start_build(session, state, args)
        self.assertEqual(ecr.get_registry_scanning_configuration.call_count, 2)
        s3.upload_file.assert_called_once()
        self.assertEqual(
            codebuild.start_build.call_args.kwargs["environmentVariablesOverride"],
            [{"name": "INSPECTOR_SCAN_MODE", "value": "skip", "type": "PLAINTEXT"}],
        )
        from botocore.validate import validate_parameters

        model = boto3.client(
            "codebuild",
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        ).meta.service_model.operation_model("StartBuild")
        validate_parameters(codebuild.start_build.call_args.kwargs, model.input_shape)

    def test_pipeline_skip_records_unscanned_images_and_runs_tasks(self):
        images = {name: {"uri": f"image:{name}"} for name in pipeline.SCENARIOS}
        session = Mock()
        ecr = Mock()
        session.client.side_effect = lambda name: ecr if name == "ecr" else Mock()
        report = {
            "scenarios": [
                {"name": name, "status": "PASS"}
                for name in ("baseline", "pinned-failure", "conventional", "lightwell")
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def scenario_command(*args, **kwargs):
                result = root / "evidence/run/results.json"
                result.parent.mkdir(parents=True)
                result.write_text(json.dumps(report))

            with (
                patch.object(pipeline, "ROOT", root),
                patch.dict(os.environ, {"INSPECTOR_SCAN_MODE": "skip"}, clear=True),
                patch.object(pipeline.boto3, "Session", return_value=session),
                patch.object(
                    pipeline, "prepare_codeartifact", return_value=("settings", "hash")
                ),
                patch.object(pipeline, "command", side_effect=scenario_command),
                patch.object(pipeline, "build_images", return_value=images),
                patch.object(
                    pipeline, "run_fargate", return_value={"status": "PASS"}
                ) as run,
                patch.object(pipeline, "scan_images") as scan,
            ):
                self.assertEqual(pipeline.main(), 0)
            evidence = root / "evidence/aws"
            summary = json.loads((evidence / "integration.json").read_text())
            comparison = json.loads((evidence / "scan-comparison.json").read_text())
        self.assertEqual(summary["status"], "INTEGRATION_PASS_INSPECTOR_SKIPPED")
        self.assertEqual(summary["stages"]["inspector"], "SKIPPED")
        self.assertFalse(summary["security_fix_verified"])
        self.assertEqual(set(comparison), set(images))
        self.assertTrue(
            all(result["interpretation"] == "SKIPPED" for result in comparison.values())
        )
        self.assertEqual(summary["scans"], comparison)
        self.assertEqual(run.call_count, 2)
        scan.assert_not_called()
        ecr.get_registry_scanning_configuration.assert_not_called()
        self.assertNotIn(
            "inspector2", [call.args[0] for call in session.client.call_args_list]
        )

    def test_pipeline_default_requires_coverage_and_rejects_invalid_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Mock()
            ecr = session.client.return_value
            ecr.get_registry_scanning_configuration.return_value = {
                "scanningConfiguration": {"scanType": "BASIC"}
            }
            with (
                patch.object(pipeline, "ROOT", Path(directory)),
                patch.object(pipeline.boto3, "Session", return_value=session),
                patch.object(pipeline, "prepare_codeartifact") as prepare,
            ):
                for env, message in (
                    ({"ECR_REPOSITORY": "demo"}, "enhanced scanning"),
                    ({"INSPECTOR_SCAN_MODE": "typo"}, "Invalid INSPECTOR_SCAN_MODE"),
                ):
                    with patch.dict(os.environ, env, clear=True):
                        self.assertEqual(pipeline.main(), 1)
                    summary = json.loads(
                        (Path(directory) / "evidence/aws/integration.json").read_text()
                    )
                    self.assertEqual(summary["status"], "FAILED")
                    self.assertIn(message, summary["error"])
                prepare.assert_not_called()

    def test_missing_scenario_is_not_success(self):
        with self.assertRaises(RuntimeError):
            pipeline.require_local_results(
                {"scenarios": [{"name": "lightwell", "status": "PASS"}]}
            )

    def test_any_failed_scenario_blocks_images(self):
        report = {
            "scenarios": [
                {"name": name, "status": "PASS"}
                for name in ("baseline", "pinned-failure", "conventional", "lightwell")
            ]
        }
        pipeline.require_local_results(report)
        report["scenarios"][1]["status"] = "FAIL"
        with self.assertRaises(RuntimeError):
            pipeline.require_local_results(report)

    def test_payment_output_checks_all_fields(self):
        self.assertTrue(
            pipeline.payment_ok(
                "Transaction Id: PX-1001\nAmount: 129.99 USD\nStatus: APPROVED"
            )
        )
        self.assertFalse(
            pipeline.payment_ok(
                "Transaction Id: PX-1001\nAmount: 129.99 USD\nStatus: DECLINED"
            )
        )

    def test_scan_deadline_never_becomes_clean_result(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with self.assertRaises(RuntimeError):
                pipeline.scan_images(
                    Mock(),
                    {"lightwell": {"digest": "sha256:test"}},
                    evidence,
                    timeout=0,
                )
            result = json.loads((evidence / "scan-comparison.json").read_text())
            self.assertEqual(result["lightwell"]["interpretation"], "INCONCLUSIVE")

    def test_active_scan_without_timestamp_is_not_complete(self):
        client = Mock()
        client.describe_image_scan_findings.return_value = {
            "imageScanStatus": {"status": "ACTIVE"},
            "imageScanFindings": {},
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"ECR_REPOSITORY": "demo"}),
            patch.object(pipeline.time, "monotonic", side_effect=[0, 0, 100]),
            patch.object(pipeline.time, "sleep"),
            self.assertRaises(RuntimeError),
        ):
            pipeline.scan_images(
                client,
                {"baseline": {"digest": "sha256:test"}},
                Path(directory),
                timeout=1,
            )

    def test_no_finding_does_not_claim_backport_verified(self):
        client = boto3.client(
            "ecr",
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        digest = "sha256:" + "a" * 64
        with (
            Stubber(client) as stub,
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"ECR_REPOSITORY": "demo"}),
        ):
            stub.add_response(
                "describe_image_scan_findings",
                {
                    "imageScanStatus": {"status": "ACTIVE"},
                    "imageScanFindings": {
                        "imageScanCompletedAt": 1,
                        "enhancedFindings": [],
                    },
                },
                {
                    "repositoryName": "demo",
                    "imageId": {"imageDigest": digest},
                    "maxResults": 1000,
                },
            )
            result = pipeline.scan_images(
                client, {"lightwell": {"digest": digest}}, Path(directory)
            )
            self.assertEqual(result["lightwell"]["interpretation"], "NOT_REPORTED")
            self.assertEqual(
                result["lightwell"]["backport_recognition"], "NOT_ESTABLISHED"
            )
            stub.assert_no_pending_responses()

    def test_fargate_launch_failure_is_not_success_and_definition_cleaned(self):
        ecs = Mock()
        ecs.register_task_definition.return_value = {
            "taskDefinition": {"taskDefinitionArn": "arn:test:definition"}
        }
        ecs.run_task.return_value = {"tasks": [], "failures": [{"reason": "capacity"}]}
        environment = {
            key: "test"
            for key in (
                "DEMO_NAME",
                "TASK_EXECUTION_ROLE",
                "TASK_LOG_GROUP",
                "AWS_DEFAULT_REGION",
                "ECS_CLUSTER",
                "TASK_SUBNET",
                "TASK_SECURITY_GROUP",
            )
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, environment),
            self.assertRaises(RuntimeError),
        ):
            pipeline.run_fargate(
                ecs, Mock(), {"uri": "repo@sha256:test"}, "lightwell", Path(directory)
            )
        ecs.deregister_task_definition.assert_called_once_with(
            taskDefinition="arn:test:definition"
        )

    def test_codeartifact_identical_assets_are_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            package_dir = (
                work / "seed/com/fasterxml/woodstox/woodstox-core" / pipeline.PATCH
            )
            package_dir.mkdir(parents=True)
            for ext in ("jar", "pom"):
                (package_dir / f"woodstox-core-{pipeline.PATCH}.{ext}").write_bytes(
                    b"same"
                )
            client = Mock()
            client.get_repository_endpoint.return_value = {
                "repositoryEndpoint": "https://example.test/repo/"
            }
            client.get_authorization_token.return_value = {
                "authorizationToken": "secret"
            }
            client.get_package_version_asset.side_effect = [
                {"asset": io.BytesIO(b"same")},
                {"asset": io.BytesIO(b"same")},
            ]
            with (
                patch.dict(os.environ, {"CA_DOMAIN": "demo", "CA_REPOSITORY": "repo"}),
                patch.object(pipeline, "command") as run,
            ):
                settings, _ = pipeline.prepare_codeartifact(client, work, work)
                self.assertEqual(run.call_count, 1)  # Fetch only; no republish.
                self.assertNotIn("secret", settings.read_text())
            evidence = json.loads((work / "codeartifact.json").read_text())
            self.assertTrue(evidence["reused_identical_package"])

    def test_codeartifact_conflicting_assets_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            package_dir = (
                work / "seed/com/fasterxml/woodstox/woodstox-core" / pipeline.PATCH
            )
            package_dir.mkdir(parents=True)
            for ext in ("jar", "pom"):
                (package_dir / f"woodstox-core-{pipeline.PATCH}.{ext}").write_bytes(
                    b"vendor"
                )
            client = Mock()
            client.get_repository_endpoint.return_value = {
                "repositoryEndpoint": "https://example.test/repo/"
            }
            client.get_authorization_token.return_value = {
                "authorizationToken": "secret"
            }
            client.get_package_version_asset.side_effect = [
                {"asset": io.BytesIO(b"different")},
                {"asset": io.BytesIO(b"different")},
            ]
            with (
                patch.dict(os.environ, {"CA_DOMAIN": "demo", "CA_REPOSITORY": "repo"}),
                patch.object(pipeline, "command"),
                self.assertRaises(RuntimeError),
            ):
                pipeline.prepare_codeartifact(client, work, work)

    def test_fargate_success_checks_output_and_api_shapes(self):
        from botocore.validate import validate_parameters

        ecs_model = boto3.client(
            "ecs",
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        logs_model = boto3.client(
            "logs",
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        ecs, logs = Mock(), Mock()

        def validated(client, operation, response):
            def call(**kwargs):
                model = client.meta.service_model.operation_model(operation)
                validate_parameters(kwargs, model.input_shape)
                return response

            return call

        ecs.register_task_definition.side_effect = validated(
            ecs_model,
            "RegisterTaskDefinition",
            {"taskDefinition": {"taskDefinitionArn": "arn:definition"}},
        )
        ecs.run_task.side_effect = validated(
            ecs_model,
            "RunTask",
            {"tasks": [{"taskArn": "arn:task/id"}], "failures": []},
        )
        ecs.describe_tasks.side_effect = validated(
            ecs_model,
            "DescribeTasks",
            {"tasks": [{"lastStatus": "STOPPED", "containers": [{"exitCode": 0}]}]},
        )
        ecs.deregister_task_definition.side_effect = validated(
            ecs_model, "DeregisterTaskDefinition", {}
        )
        logs.get_log_events.side_effect = validated(
            logs_model,
            "GetLogEvents",
            {
                "events": [
                    {"message": "Transaction Id: PX-1001"},
                    {"message": "Amount: 129.99 USD"},
                    {"message": "Status: APPROVED"},
                ]
            },
        )
        environment = {
            key: "test"
            for key in (
                "DEMO_NAME",
                "TASK_EXECUTION_ROLE",
                "TASK_LOG_GROUP",
                "AWS_DEFAULT_REGION",
                "ECS_CLUSTER",
                "TASK_SUBNET",
                "TASK_SECURITY_GROUP",
            )
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, environment),
        ):
            result = pipeline.run_fargate(
                ecs, logs, {"uri": "repo@sha256:test"}, "lightwell", Path(directory)
            )
        self.assertEqual(result["status"], "PASS")
        ecs.stop_task.assert_not_called()
        ecs.deregister_task_definition.assert_called_once()


if __name__ == "__main__":
    unittest.main()

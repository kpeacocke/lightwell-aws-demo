"""Offline adversarial checks: advisory metadata must never become a verdict."""

import copy
import io
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Callable
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
import advisory  # noqa: E402
import pipeline  # noqa: E402


def record() -> dict[str, Any]:
    # Synthetic minimal fixture, not a cached vendor/security attestation.
    return {
        "id": advisory.ADVISORY,
        "upstream": [advisory.CVE],
        "affected": [
            {
                "package": {"name": advisory.PACKAGE, "ecosystem": advisory.ECOSYSTEM},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": advisory.BASE},
                            {"fixed": advisory.VERSION},
                        ],
                    }
                ],
                "database_specific": {
                    "lightwell": {
                        "backport_base_version": advisory.BASE,
                        "remediated_version": advisory.VERSION,
                    }
                },
            }
        ],
    }


def inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    digest = "sha256:" + "a" * 64
    finding: dict[str, Any] = {
        "findingArn": "test-finding",
        "status": "ACTIVE",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": advisory.CVE,
            "vulnerablePackages": [
                {
                    "name": advisory.PACKAGE,
                    "version": advisory.VERSION,
                    "packageManager": "JAVA",
                }
            ],
        },
        "resources": [
            {
                "type": "AWS_ECR_CONTAINER_IMAGE",
                "details": {"awsEcrContainerImage": {"imageHash": digest}},
            }
        ],
    }
    return (
        {"lightwell": {"interpretation": "REPORTED", "target_findings": [finding]}},
        {"lightwell": {"digest": digest}},
    )


class AdvisoryTests(unittest.TestCase):
    def test_pipeline_keeps_security_review_and_raw_inspector(self):
        scans, images = inputs()
        images["conventional"] = {"uri": "test:conventional"}
        session = Mock()
        client = session.client.return_value
        client.get_paginator.return_value.paginate.return_value = []
        report = {
            "scenarios": [
                {"name": n, "status": "PASS"}
                for n in ("baseline", "pinned-failure", "conventional", "lightwell")
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence/aws"

            def build(*args: Any) -> dict[str, Any]:
                del args
                pipeline.write_json(evidence / "images.json", images)
                return images

            def scan(*args: Any) -> dict[str, Any]:
                del args
                pipeline.write_json(evidence / "scan-comparison.json", scans)
                (evidence / "lightwell-inspector.json").write_bytes(b"raw-sentinel")
                return scans

            def command(*args: Any, **kwargs: Any) -> None:
                del args, kwargs
                pipeline.write_json(root / "evidence/run/results.json", report)

            with (
                patch.object(pipeline, "ROOT", root),
                patch.dict(
                    os.environ,
                    {"INSPECTOR_SCAN_MODE": "required", "ECR_REPOSITORY": "demo"},
                ),
                patch.object(pipeline.boto3, "Session", return_value=session),
                patch.object(pipeline, "enhanced_for_repository", return_value=True),
                patch.object(
                    session.client.return_value,
                    "get_registry_scanning_configuration",
                    return_value={},
                ),
                patch.object(
                    pipeline, "prepare_codeartifact", return_value=("settings", "hash")
                ),
                patch.object(pipeline, "command", side_effect=command),
                patch.object(pipeline, "build_images", side_effect=build),
                patch.object(pipeline, "run_fargate", return_value={"status": "PASS"}),
                patch.object(pipeline, "scan_images", side_effect=scan),
                patch.object(
                    advisory, "fetch", return_value=json.dumps(record()).encode()
                ),
            ):
                # The existing scanner configuration response is still required.
                client.get_registry_scanning_configuration.return_value = {
                    "scanningConfiguration": {}
                }
                self.assertEqual(pipeline.main(), 0)
            summary = json.loads((evidence / "integration.json").read_text())
            self.assertEqual(
                summary["status"], "INTEGRATION_PASS_SECURITY_REVIEW_REQUIRED"
            )
            self.assertFalse(summary["security_fix_verified"])
            self.assertEqual(
                summary["lightwell_advisory"]["correlation"]["state"], "VERIFIED"
            )
            self.assertEqual(
                (evidence / "lightwell-inspector.json").read_bytes(), b"raw-sentinel"
            )

    def test_exact_vendor_claim(self):
        self.assertEqual(advisory.advisory_claim(record())["state"], "VERIFIED")

    def test_wrong_or_missing_advisory_fields(self):
        changes: list[Callable[[dict[str, Any]], None]] = [
            lambda r: r.update(id="other"),
            lambda r: r.update(withdrawn="2026-01-01T00:00:00Z"),
            lambda r: r.update(upstream=[]),
            lambda r: r["affected"][0]["package"].update(name="other:woodstox-core"),
            lambda r: r["affected"][0]["package"].update(ecosystem="Maven"),
            lambda r: r["affected"][0]["database_specific"]["lightwell"].update(
                backport_base_version="6.2.2"
            ),
            lambda r: r["affected"][0]["database_specific"]["lightwell"].update(
                remediated_version="6.0.3.rhlw-00002"
            ),
            lambda r: r["affected"][0].update(ranges=[]),
            lambda r: r["affected"][0].update(versions=[advisory.VERSION]),
        ]
        for change in changes:
            with self.subTest(change=change):
                data = record()
                change(data)
                self.assertEqual(advisory.advisory_claim(data)["state"], "UNVERIFIED")

    def test_cannot_combine_fields_across_packages(self):
        data = record()
        other = copy.deepcopy(data["affected"][0])
        data["affected"][0]["ranges"] = []
        other["package"]["name"] = "wrong:package"
        data["affected"].append(other)
        self.assertEqual(advisory.advisory_claim(data)["state"], "UNVERIFIED")

    def test_inspector_requires_exact_identity_and_digest(self):
        scans, images = inputs()
        self.assertEqual(advisory.inspector_match(scans, images)["state"], "VERIFIED")
        for key, value in (
            ("name", "woodstox-core"),
            ("version", "6.0.3"),
            ("packageManager", "NPM"),
        ):
            wrong = copy.deepcopy(scans)
            wrong["lightwell"]["target_findings"][0]["packageVulnerabilityDetails"][
                "vulnerablePackages"
            ][0][key] = value
            self.assertEqual(
                advisory.inspector_match(wrong, images)["state"], "UNVERIFIED"
            )
        images["lightwell"]["digest"] = "sha256:" + "b" * 64
        self.assertEqual(advisory.inspector_match(scans, images)["state"], "UNVERIFIED")
        scans["lightwell"]["target_findings"] = []
        self.assertEqual(advisory.inspector_match(scans, images)["state"], "UNVERIFIED")
        for interpretation in ("SKIPPED", "INCONCLUSIVE"):
            scans["lightwell"]["interpretation"] = interpretation
            self.assertEqual(
                advisory.inspector_match(scans, images)["state"], "UNAVAILABLE"
            )

    def run_lookup(
        self, raw: bytes | None = None, error: Exception | None = None
    ) -> tuple[dict[str, Any], Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        scans, images = inputs()
        scan_path, images_path = root / "scans.json", root / "images.json"
        scan_path.write_text(json.dumps(scans))
        images_path.write_text(json.dumps(images))
        original = scan_path.read_bytes()
        with patch.object(advisory, "fetch", return_value=raw, side_effect=error):
            result = advisory.reconcile(scan_path, images_path, root / "lookup")
        self.assertEqual(scan_path.read_bytes(), original)
        self.assertFalse(result["security_fix_verified"])
        self.assertEqual(result["binary_provenance"]["state"], "UNVERIFIED")
        self.assertEqual(result["action"], "REVIEW_REQUIRED")
        self.assertNotIn("secret-sentinel", json.dumps(result))
        return result, root

    def test_preserves_raw_response_and_inputs(self):
        raw = json.dumps(record()).encode()
        result, root = self.run_lookup(raw=raw)
        self.assertEqual(result["correlation"]["state"], "VERIFIED")
        self.assertEqual((root / "lookup/osv-response.json").read_bytes(), raw)
        with (
            self.assertRaises(FileExistsError),
            patch.object(advisory, "fetch") as fetch,
        ):
            advisory.reconcile(
                root / "scans.json", root / "images.json", root / "lookup"
            )
        fetch.assert_not_called()

    def test_unavailable_and_malformed_never_pass(self):
        for error in (
            URLError("secret-sentinel"),
            TimeoutError("secret-sentinel"),
            HTTPError(advisory.URL, 401, "secret-sentinel", Message(), None),
            HTTPError(advisory.URL, 404, "missing", Message(), None),
            HTTPError(advisory.URL, 429, "rate limited", Message(), None),
            HTTPError(advisory.URL, 500, "server", Message(), None),
        ):
            result, _ = self.run_lookup(error=error)
            self.assertEqual(result["correlation"]["state"], "UNAVAILABLE")
        for raw in (b"not json", b"[]", b'{"affected": null}', b"{}"):
            result, _ = self.run_lookup(raw=raw)
            self.assertNotEqual(result["correlation"]["state"], "VERIFIED")

    def test_network_request_has_no_auth_and_is_bounded(self):
        response = Mock()
        response.read.return_value = b"{}"
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(advisory, "build_opener", return_value=opener):
            self.assertEqual(advisory.fetch(), b"{}")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, advisory.URL)
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
            response.read.assert_called_once_with(advisory.MAX_BYTES + 1)
            response.read.return_value = b"x" * (advisory.MAX_BYTES + 1)
            with self.assertRaises(ValueError):
                advisory.fetch()
        self.assertIsNone(
            advisory.NoRedirect().redirect_request(
                Request("https://example.com"),
                io.BytesIO(),
                302,
                "",
                HTTPMessage(),
                "https://example.com",
            )
        )

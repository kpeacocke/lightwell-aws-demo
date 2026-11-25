#!/usr/bin/env python3
"""Read-only, exact-release advisory correlation; never a security verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from http.client import HTTPException, HTTPMessage
from pathlib import Path
from typing import IO, Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

CVE = "CVE-2022-40152"
PACKAGE = "com.fasterxml.woodstox:woodstox-core"
VERSION = "6.0.3.rhlw-00001"
BASE = "6.0.3"
ECOSYSTEM = "Red Hat Lightwell:Maven"
ADVISORY = "RHLW-2026-403d1e66c95ef9bb"
URL = f"https://api.osv.dev/v1/vulns/{ADVISORY}"
MAX_BYTES = 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        return None


def fetch() -> bytes:
    """Fixed public endpoint, no credentials, no redirects, bounded response."""
    request = Request(URL, headers={"Accept": "application/json"})
    with build_opener(NoRedirect).open(request, timeout=15) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("response_too_large")
    return raw


def state(status: str, reason: str) -> dict[str, str]:
    return {"state": status, "reason": reason}


def advisory_claim(record: dict[str, Any]) -> dict[str, str]:
    """Require exact identity and consistent release metadata on the SAME entry."""
    if record.get("id") != ADVISORY or record.get("withdrawn"):
        return state("UNVERIFIED", "Unexpected or withdrawn advisory")
    upstream = record.get("upstream", [])
    if not isinstance(upstream, list) or CVE not in upstream:
        return state("UNVERIFIED", "Target CVE absent from upstream field")
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        lineage = affected.get("database_specific", {}).get("lightwell", {})
        if (
            package.get("name") != PACKAGE
            or package.get("ecosystem") != ECOSYSTEM
            or lineage.get("backport_base_version") != BASE
            or lineage.get("remediated_version") != VERSION
        ):
            continue
        # Deliberately no version ordering or extrapolation to later builds.
        ranges = affected.get("ranges", [])
        fixed = any(
            r.get("type") == "ECOSYSTEM" and {"fixed": VERSION} in r.get("events", [])
            for r in ranges
        )
        explicitly_affected = any(
            VERSION in entry.get("versions", [])
            for entry in record.get("affected", [])
            if entry.get("package", {}).get("name") == PACKAGE
            and entry.get("package", {}).get("ecosystem") == ECOSYSTEM
        )
        if fixed and not explicitly_affected:
            return state(
                "VERIFIED", "Exact vendor advisory claim matched; not binary proof"
            )
    return state("UNVERIFIED", "No consistent exact package/base/fixed-release match")


def inspector_match(scans: dict[str, Any], images: dict[str, Any]) -> dict[str, Any]:
    scan = scans.get("lightwell", {})
    if scan.get("interpretation") in ("SKIPPED", "INCONCLUSIVE") or not scan:
        return {
            **state("UNAVAILABLE", "Inspector scan skipped or incomplete"),
            "matches": [],
        }
    expected = images.get("lightwell", {}).get("digest")
    matches: list[dict[str, Any]] = []
    for finding in scan.get("target_findings", []):
        details = finding.get("packageVulnerabilityDetails", {})
        if details.get("vulnerabilityId") != CVE:
            continue
        for package in details.get("vulnerablePackages", []):
            if (
                package.get("name") != PACKAGE
                or package.get("version") != VERSION
                or package.get("packageManager") != "JAVA"
            ):
                continue
            digests = [
                resource.get("details", {})
                .get("awsEcrContainerImage", {})
                .get("imageHash")
                for resource in finding.get("resources", [])
                if resource.get("type") == "AWS_ECR_CONTAINER_IMAGE"
            ]
            bound = bool(
                isinstance(expected, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", expected)
                and expected in digests
                and finding.get("findingArn")
            )
            matches.append(
                {
                    "finding_arn": finding.get("findingArn"),
                    "finding_status": finding.get("status"),
                    "severity": finding.get("severity"),
                    "package": package,
                    "image_digests": digests,
                    "image_binding": "VERIFIED" if bound else "UNVERIFIED",
                }
            )
    verified = any(m["image_binding"] == "VERIFIED" for m in matches)
    return {
        **state(
            "VERIFIED" if verified else "UNVERIFIED",
            "Exact Inspector package/CVE/image match"
            if verified
            else "No exact finding bound to the expected image digest",
        ),
        "expected_image_digest": expected,
        "matches": matches,
    }


def reconcile(scan_path: Path, images_path: Path, output: Path) -> dict[str, Any]:
    """Keep inputs byte-for-byte; write each lookup to a new directory."""
    scan_raw, images_raw = scan_path.read_bytes(), images_path.read_bytes()
    scans_value: object = json.loads(scan_raw)
    images_value: object = json.loads(images_raw)
    if not isinstance(scans_value, dict) or not isinstance(images_value, dict):
        raise ValueError("Expected scan-comparison and images JSON objects")
    scans = cast(dict[str, Any], scans_value)
    images = cast(dict[str, Any], images_value)
    output.mkdir(parents=True, exist_ok=False)
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "target": {"cve": CVE, "package": PACKAGE, "version": VERSION},
        "source": {"url": URL, "advisory_id": ADVISORY, "authentication": "none"},
        "inputs": {
            "scan_comparison_sha256": hashlib.sha256(scan_raw).hexdigest(),
            "images_sha256": hashlib.sha256(images_raw).hexdigest(),
        },
        "inspector": inspector_match(scans, images),
        "binary_provenance": state("UNVERIFIED", "No signed provenance validated"),
        "security_fix_verified": False,
        "action": "REVIEW_REQUIRED",
        "inspector_findings_modified": False,
    }
    raw = None
    try:
        raw = fetch()
        evidence["source"]["response_sha256"] = hashlib.sha256(raw).hexdigest()
        record_value: object = json.loads(raw)
        if not isinstance(record_value, dict):
            raise ValueError("invalid_record")
        record = cast(dict[str, Any], record_value)
        evidence["lookup"] = state("VERIFIED", "Public OSV response retrieved")
        evidence["source"]["advisory_modified"] = record.get("modified")
        evidence["vendor_advisory_claim"] = advisory_claim(record)
    except (
        HTTPError,
        HTTPException,
        URLError,
        OSError,
        ValueError,
        RecursionError,
        TypeError,
        AttributeError,
    ) as error:
        # Never serialize exception text, headers, environment, or HTTP error bodies.
        reason = (
            f"http_{error.code}"
            if isinstance(error, HTTPError)
            else type(error).__name__
        )
        if isinstance(error, HTTPError):
            error.close()
        evidence["lookup"] = state("UNAVAILABLE", reason)
        evidence["vendor_advisory_claim"] = state(
            "UNAVAILABLE", "No usable advisory response"
        )
    if raw is not None:
        (output / "osv-response.json").write_bytes(raw)
    states = [evidence[k]["state"] for k in ("inspector", "vendor_advisory_claim")]
    result = (
        "UNAVAILABLE"
        if "UNAVAILABLE" in states
        else ("VERIFIED" if states == ["VERIFIED", "VERIFIED"] else "UNVERIFIED")
    )
    evidence["correlation"] = state(
        result,
        "Metadata correlation only; retain Inspector finding for security review",
    )
    (output / "reconciliation.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-comparison", type=Path, required=True)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, required=True, help="New evidence directory"
    )
    args = parser.parse_args()
    result = reconcile(args.scan_comparison, args.images, args.output)
    print(
        json.dumps({"correlation": result["correlation"], "output": str(args.output)})
    )


if __name__ == "__main__":
    main()

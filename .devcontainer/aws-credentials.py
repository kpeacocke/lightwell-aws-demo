#!/usr/bin/env python3
"""Provide the container's environment credentials to an explicit AWS profile."""

import json
import os
import sys

try:
    credentials: dict[str, str | int] = {
        "Version": 1,
        "AccessKeyId": os.environ["AWS_ACCESS_KEY_ID"],
        "SecretAccessKey": os.environ["AWS_SECRET_ACCESS_KEY"],
    }
except KeyError as error:
    sys.exit(f"Missing AWS environment variable: {error.args[0]}")

if not credentials["AccessKeyId"] or not credentials["SecretAccessKey"]:
    sys.exit("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must not be empty")

if os.environ.get("AWS_SESSION_TOKEN"):
    credentials["SessionToken"] = os.environ["AWS_SESSION_TOKEN"]

print(json.dumps(credentials))

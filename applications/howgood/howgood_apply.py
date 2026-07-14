"""Prepare a signed HowGood application request without sending it by default.

Signing requires the environment variable:
HOWGOOD_APPLICATION_SECRET=<value from the official application instructions>

Submission requires BOTH --submit and the environment variable:
HOWGOOD_ALLOW_SUBMIT=I_HAVE_EXPLICIT_APPROVAL
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ENDPOINT = "https://howgood-apply-api.howgood.workers.dev/apply"
SIGNING_SECRET_ENV = "HOWGOOD_APPLICATION_SECRET"
APPROVAL_ENV = "HOWGOOD_ALLOW_SUBMIT"
APPROVAL_VALUE = "I_HAVE_EXPLICIT_APPROVAL"

REQUIRED_TEXT_FIELDS = (
    "name",
    "email",
    "resume",
    "location",
    "linkedin",
    "codeLink",
)
URL_FIELDS = ("resume", "linkedin", "codeLink", "repos")
YEAR_FIELDS = ("yearsPython", "yearsDjango")


def load_payload(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("The configuration root must be a JSON object.")
    return payload


def validate_payload(payload: dict[str, Any]) -> None:
    errors: list[str] = []

    for field in REQUIRED_TEXT_FIELDS:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be a non-empty string")

    for field in URL_FIELDS:
        value = payload.get(field)
        if value in (None, "") and field == "repos":
            continue
        if not isinstance(value, str) or not value.startswith("https://"):
            errors.append(f"{field} must be an https:// URL")

    for field in YEAR_FIELDS:
        value = payload.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{field} must be a non-negative integer")

    if errors:
        raise ValueError("Invalid application payload:\n- " + "\n- ".join(errors))


def encode_payload(payload: dict[str, Any]) -> bytes:
    """Return the exact compact JSON bytes used for both signing and sending."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def load_signing_secret() -> bytes:
    value = os.environ.get(SIGNING_SECRET_ENV)
    if not value:
        raise ValueError(
            f"{SIGNING_SECRET_ENV} must be set from the official application "
            "instructions before signing."
        )
    return value.encode("utf-8")


def sign_body(body: bytes, signing_secret: bytes) -> str:
    return hmac.new(
        signing_secret,
        body,
        hashlib.sha256,
    ).hexdigest()


def self_test(signing_secret: bytes) -> None:
    payload = {
        "name": "Example Candidate",
        "email": "candidate@example.com",
        "resume": "https://example.com/resume.pdf",
        "location": "Example City, US",
        "linkedin": "https://www.linkedin.com/in/example",
        "codeLink": "https://github.com/example/howgood-apply",
        "yearsPython": 5,
        "yearsDjango": 3,
        "repos": "https://github.com/example",
        "notes": "Local signature test only.",
    }
    validate_payload(payload)
    body = encode_payload(payload)
    first = sign_body(body, signing_secret)
    second = sign_body(body, signing_secret)
    if first != second or len(first) != 64:
        raise AssertionError("HMAC signing is not deterministic SHA-256 hex output.")
    print("Self-test passed. No network request was made.")


def submit(body: bytes, signature: str) -> tuple[int, str]:
    request = urllib.request.Request(
        ENDPOINT,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HMAC-Signature": signature,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", type=Path, help="Private JSON payload")
    parser.add_argument("--submit", action="store_true", help="Send after approval gate")
    parser.add_argument("--self-test", action="store_true", help="Test signing locally")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        try:
            signing_secret = load_signing_secret()
            self_test(signing_secret)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0
    if args.config is None:
        print("A config path is required unless --self-test is used.", file=sys.stderr)
        return 2

    try:
        payload = load_payload(args.config)
        validate_payload(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    body = encode_payload(payload)
    print(f"Application payload validated and encoded ({len(body)} bytes).")

    if not args.submit:
        print("DRY RUN ONLY. No network request was made.")
        return 0

    if os.environ.get(APPROVAL_ENV) != APPROVAL_VALUE:
        print(
            f"Submission blocked. Set {APPROVAL_ENV}={APPROVAL_VALUE} only after "
            "Keenan explicitly approves the final application.",
            file=sys.stderr,
        )
        return 3

    try:
        signing_secret = load_signing_secret()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    signature = sign_body(body, signing_secret)
    status, response_body = submit(body, signature)
    print("HTTP status:", status)
    print("Response:", response_body)
    return 0 if status == 201 else 1


if __name__ == "__main__":
    raise SystemExit(main())

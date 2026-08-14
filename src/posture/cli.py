"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
)

from posture import __version__, render
from posture.demo.loader import DEMO_ACCOUNT_ID, DemoEc2, DemoS3, DemoS3Control
from posture.runner import run_all

_DESCRIPTION = (
    "Read-only AWS posture checks. Run this only against accounts you own "
    "or are authorized to assess."
)

_EXIT_OK = 0
_EXIT_CANNOT_START = 1
_EXIT_INCOMPLETE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="posture", description=_DESCRIPTION)
    parser.add_argument(
        "--demo",
        action="store_true",
        help="run against bundled synthetic fixtures, no AWS credentials needed",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--region", default=None, help="AWS region for live runs")
    return parser


def _demo_clients() -> tuple:
    metadata = {
        "mode": "demo",
        "account": DEMO_ACCOUNT_ID,
        "region": "us-east-1",
        "tool_version": __version__,
    }
    return DemoS3(), DemoEc2(), DemoS3Control(), DEMO_ACCOUNT_ID, metadata


def _live_clients(region: str | None) -> tuple:
    import boto3

    session = boto3.Session(region_name=region)
    identity = session.client("sts").get_caller_identity()
    account = identity["Account"]
    metadata = {
        "mode": "live",
        "account": account,
        "region": session.region_name or "unknown",
        "tool_version": __version__,
    }
    return (
        session.client("s3"),
        session.client("ec2"),
        session.client("s3control"),
        account,
        metadata,
    )


def session_problem(error: Exception, region: str | None) -> str:
    """One line a reader can act on, in place of a botocore traceback.

    Failing to start is the most common first experience of a command line
    tool, and thirty lines of stack answers a question nobody asked.
    """
    if isinstance(error, NoCredentialsError):
        return "no AWS credentials found. Configure credentials, or run with --demo."
    if isinstance(error, NoRegionError):
        return "no AWS region set. Pass --region, or configure a default region."
    if isinstance(error, EndpointConnectionError):
        where = region or "the configured region"
        return f"could not reach the AWS endpoint for {where}. Check the region and network."
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code") or "unknown error"
        return f"AWS refused sts:GetCallerIdentity ({code}). Check the credentials and policy."
    return f"could not start an AWS session ({type(error).__name__})."


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        clients = _demo_clients() if args.demo else _live_clients(args.region)
    except (BotoCoreError, ClientError) as error:
        sys.stderr.write(f"posture: {session_problem(error, args.region)}\n")
        return _EXIT_CANNOT_START

    s3, ec2, s3control, account, metadata = clients
    result = run_all(s3, ec2, s3control, account)
    if args.json:
        output = render.to_json(result.findings, metadata, result.errors)
    else:
        output = render.to_table(result.findings, result.errors)
    sys.stdout.write(output)

    # A run with gaps in its coverage exits nonzero, so a pipeline treating
    # exit 0 as "assessed and clean" cannot be told that by a partial scan.
    return _EXIT_OK if result.complete else _EXIT_INCOMPLETE


def run() -> None:
    raise SystemExit(main())

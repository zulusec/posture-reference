"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from posture import __version__, render
from posture.demo.loader import DEMO_ACCOUNT_ID, DemoEc2, DemoS3, DemoS3Control
from posture.runner import run_all

_DESCRIPTION = (
    "Read-only AWS posture checks. Run this only against accounts you own "
    "or are authorized to assess."
)


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    clients = _demo_clients() if args.demo else _live_clients(args.region)
    s3, ec2, s3control, account, metadata = clients
    findings = run_all(s3, ec2, s3control, account)
    output = render.to_json(findings, metadata) if args.json else render.to_table(findings)
    sys.stdout.write(output)
    return 0


def run() -> None:
    raise SystemExit(main())

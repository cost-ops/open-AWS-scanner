"""CLI entry point for open-aws-scanner."""
import argparse
import os
import sys
import json


def main():
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="open-aws-scanner",
        description="Find unused AWS resources costing you money.",
    )
    parser.add_argument("--version", "-v", action="version", version=f"open-aws-scanner {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # serve - start the API server
    serve_parser = subparsers.add_parser("serve", help="Start the API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    serve_parser.add_argument("--config", default="config.env", help="Path to config.env file")

    # scan - run a one-shot scan (no server)
    scan_parser = subparsers.add_parser("scan", help="Run a one-shot scan and print results")
    scan_parser.add_argument("--regions", help="Comma-separated AWS regions (overrides config)")
    scan_parser.add_argument("--role-arn", help="AWS role ARN to assume (overrides config)")
    scan_parser.add_argument("--output", choices=["json", "table"], default="table", help="Output format")
    scan_parser.add_argument("--config", default="config.env", help="Path to config.env file")

    # init - create a config.env template
    subparsers.add_parser("init", help="Create a config.env template in the current directory")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "init":
        _cmd_init()
    elif args.command == "serve":
        _cmd_serve(args)
    elif args.command == "scan":
        _cmd_scan(args)


def _cmd_init():
    """Create a config.env template."""
    config_path = os.path.join(os.getcwd(), "config.env")
    if os.path.exists(config_path):
        print(f"config.env already exists at {config_path}")
        sys.exit(1)

    template = """# Open AWS Scanner Configuration

# AWS Credentials (use IAM role ARN for cross-account scanning, or leave blank for local credentials)
AWS_ROLE_ARN=
AWS_EXTERNAL_ID=
AWS_REGIONS=us-east-1

# Optional: explicit credentials (prefer IAM roles or environment/profile instead)
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

# Scanner settings
SCAN_INTERVAL_HOURS=6
STAGE_MODE=false

# Server
HOST=0.0.0.0
PORT=8000
"""
    with open(config_path, "w") as f:
        f.write(template)
    print(f"Created {config_path}")
    print("Edit it with your AWS configuration, then run: open-aws-scanner serve")


def _cmd_serve(args):
    """Start the API server."""
    from dotenv import load_dotenv

    config_path = os.path.abspath(args.config)
    if os.path.exists(config_path):
        load_dotenv(config_path)

    os.environ.setdefault("HOST", args.host)
    os.environ.setdefault("PORT", str(args.port))

    from .database import init_db
    init_db()

    import uvicorn
    uvicorn.run(
        "open_aws_scanner.api:app",
        host=args.host,
        port=args.port,
        reload=False,
    )


def _cmd_scan(args):
    """Run a one-shot scan without starting the server."""
    from dotenv import load_dotenv

    config_path = os.path.abspath(args.config)
    if os.path.exists(config_path):
        load_dotenv(config_path)

    # CLI overrides
    if args.regions:
        os.environ["AWS_REGIONS"] = args.regions
    if args.role_arn:
        os.environ["AWS_ROLE_ARN"] = args.role_arn

    from .database import init_db
    init_db()

    # Redirect scanner logs to stderr so --output json works cleanly
    from .scanner import run_scan
    old_stdout = sys.stdout
    sys.stdout = sys.stderr
    findings = run_scan()
    sys.stdout = old_stdout

    if not findings:
        print("\nNo waste found! Your AWS account looks clean.")
        return

    if args.output == "json":
        print(json.dumps(findings, indent=2, default=str))
    else:
        _print_table(findings)


def _print_table(findings):
    """Print findings as a formatted table."""
    total_savings = sum(f.get("estimated_monthly_savings") or 0 for f in findings)

    print(f"\n{'='*80}")
    print(f" Open AWS Scanner — {len(findings)} issues found | ${total_savings:.2f}/mo potential savings")
    print(f"{'='*80}\n")

    # Group by resource type
    by_type = {}
    for f in findings:
        rtype = f["resource_type"]
        by_type.setdefault(rtype, []).append(f)

    for rtype, items in sorted(by_type.items()):
        type_savings = sum(i.get("estimated_monthly_savings") or 0 for i in items)
        print(f"  {rtype} ({len(items)} found, ${type_savings:.2f}/mo)")
        for item in items:
            savings = f"  ${item['estimated_monthly_savings']:.2f}/mo" if item.get("estimated_monthly_savings") else ""
            region = f"  [{item['region']}]" if item.get("region") else ""
            print(f"    • {item['resource_name']}: {item['reason']}{savings}{region}")
        print()

    print(f"{'─'*80}")
    print(f"  Total potential savings: ${total_savings:.2f}/month")
    print()


if __name__ == "__main__":
    main()

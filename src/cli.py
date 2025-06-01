#!/usr/bin/env python3

import argparse
from datetime import datetime as dt

from moniots_scanner import models as moniots_models
from moniots_scanner import report as moniots_report
from moniots_scanner.main import orchestrate_scan


def main():
    """Main function for the CLI interface.
    Parses arguments and calls the core scanning logic.
    """
    # Set up command-line arguments.
    args = setup_args()
    # Discover devices, run tests and filter results based on severity.
    results = orchestrate_scan(args)
    # Generate reports based on the results.
    generate_reports(results, args)


def generate_reports(results: dict, args: argparse.Namespace):
    """Generate report files based on the scan results."""
    if args.json_out:
        print(f"Generating JSON report to: {args.json_out}")
        report = moniots_report.generate_json_report(results)
        with open(args.json_out, "w") as fp:
            fp.write(report)

    if args.html_out:
        print(f"Generating HTML report to: {args.html_out}")
        report = moniots_report.generate_html_report(results, args.network, dt.now())
        with open(args.html_out, "w") as fp:
            fp.write(report)


def setup_args() -> argparse.Namespace:
    """Set up command-line arguments for the script.
    (Moved directly from the user-provided main.py)
    """
    parser = argparse.ArgumentParser(
        description="moniots: Monitoring for IoT Security",
    )
    parser.add_argument("network", help="CIDR network range (e.g. 192.168.1.0/24)")

    parser.add_argument(
        "--severity",
        dest="severity",
        type=lambda s: s.lower(),
        choices=[s.label.lower() for s in moniots_models.Severity],
        default=moniots_models.Severity.MEDIUM.label.lower(),
        help=f"Minimum severity level of alerts to include (default: {moniots_models.Severity.MEDIUM.label.lower()})",
    )

    parser.add_argument(
        "--json", dest="json_out", default=None, help="JSON report file destination"
    )

    parser.add_argument(
        "--html", dest="html_out", default=None, help="HTML report file destination"
    )

    parser.add_argument(
        "--local-zap-proxy",
        dest="local_zap_proxy",
        default=None,
        help="Local ZAP proxy (e.g. http://127.0.0.1:8080)",
    )

    parser.add_argument(
        "--zap-api-key",
        dest="zap_api_key",
        default=None,
        help="OWASP ZAP API key for ecosystem interface scans",
    )

    parser.add_argument(
        "--nvd-api-key",
        dest="nvd_api_key",
        default=None,
        help="NVD API key for CVE queries (optional, heavily reduces NVD query time)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()

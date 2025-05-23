#!/usr/bin/env python3

import argparse
from datetime import datetime as dt

import creds
import discovery
import report
import webapp
from models import Severity


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover and parse devices.
    scanned_hosts = discovery.discover_devices(args.network)
    devices = discovery.parse_device_info(scanned_hosts)

    # Run tests.
    cred_alerts = creds.batch_test_common_credentials(devices)

    # Scan for web application vulnerabilities.
    # TODO: Exclude zaproxy from itself?
    http_devices = [
        d for d in devices if any(p.service in ["http", "https"] for p in d.open_ports)
    ]

    zap_alerts = webapp.scan_web_apps(
        http_devices,
        args.zap_api_key,
        args.local_zap_proxy,
        Severity(args.severity.title()),
    )

    # Merge alert results.
    results = {d: cred_alerts.get(d, []) + zap_alerts.get(d, []) for d in devices}

    # Generate reports.
    if args.json_out:
        json_ = report.generate_json_report(results)
        with open(args.json_out, "w") as f:
            f.write(json_)

    if args.html_out:
        html = report.generate_html_report(results, args.network, dt.now())
        with open(args.html_out, "w") as f:
            f.write(html)


def setup_args():
    """Set up command-line arguments for the script."""
    parser = argparse.ArgumentParser(description="moniot: IoT vulnerability scanner")
    parser.add_argument("network", help="CIDR network range (e.g. 192.168.1.0/24)")

    parser.add_argument(
        "--json", dest="json_out", default=None, help="Write JSON report to file"
    )

    parser.add_argument(
        "--html", dest="html_out", default=None, help="Write HTML report to file"
    )

    parser.add_argument(
        "--severity",
        dest="severity",
        type=lambda s: s.lower(),
        choices=[s.value.lower() for s in Severity],
        default=Severity.LOW.value.lower(),
        help=f"Minimum severity level of alerts to include ({', '.join(s.value.lower() for s in Severity)})",
    )

    parser.add_argument(
        "--zap-api-key",
        dest="zap_api_key",
        default=None,
        help="OWASP ZAP API key for ecosystem interface scans",
    )

    parser.add_argument(
        "--local-zap-proxy",
        dest="local_zap_proxy",
        default=None,
        help="Local ZAP proxy (e.g. http://127.0.0.1:8080)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()

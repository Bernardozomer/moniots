#!/usr/bin/env python3

import argparse
from datetime import datetime as dt

import exploitdb
import creds
import discovery
import models
import nvd
import report
import zap


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover and parse devices.
    scanned_hosts = discovery.discover_devices(args.network)
    devices = discovery.parse_device_info(scanned_hosts)

    # Run tests.
    results = run_tests(args, devices)

    # Generate reports.
    if args.json_out:
        json_ = report.generate_json_report(results)
        with open(args.json_out, "w") as f:
            f.write(json_)

    if args.html_out:
        html = report.generate_html_report(results, args.network, dt.now())
        with open(args.html_out, "w") as f:
            f.write(html)


def run_tests(
    args: argparse.Namespace, devices: list[models.Device]
) -> dict[models.Device, list[models.Alert]]:
    """Run vulnerability tests on devices and return structured results."""
    # Test for common credentials.
    cred_alerts = creds.batch_test_common_credentials(devices)

    # Scan for web application vulnerabilities.
    # Filter devices to only those with HTTP/HTTPS services.
    http_devices = [
        d for d in devices if any(p.service in ["http", "https"] for p in d.open_ports)
    ]

    zap_alerts = zap.run_zap(
        http_devices,
        args.zap_api_key,
        args.local_zap_proxy,
        models.Severity.from_label(args.severity),
    )

    # Scan for product exploits.
    exploitdb_alerts = exploitdb.batch_query_exploitdb(devices)

    # Query NVD for CVEs.
    nvd_alerts = nvd.batch_query_nvd(devices, nvd_api_key=args.nvd_api_key)

    # Merge alert results using a helper function.
    return merge_alerts(devices, cred_alerts, zap_alerts, exploitdb_alerts, nvd_alerts)


def merge_alerts(devices, *alert_dicts):
    """Merge alerts from multiple sources."""

    merge = lambda device: [
        alert for source in alert_dicts for alert in source.get(device, [])
    ]

    return {device: merge(device) for device in devices}


def setup_args() -> argparse.Namespace:
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
        choices=[s.label.lower() for s in models.Severity],
        default=models.Severity.LOW.label.lower(),
        help=f"Minimum severity level of alerts to include ({', '.join(s.label.lower() for s in models.Severity)})",
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

    parser.add_argument(
        "--nvd-api-key",
        dest="nvd_api_key",
        default=None,
        help="NVD API key for CVE queries (optional, heavily reduces NVD query time)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()

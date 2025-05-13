#!/usr/bin/env python3

import argparse

import creds
import discovery
import report


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover and parse devices.
    scanned_hosts = discovery.discover_devices(args.network)
    devices = discovery.parse_device_info(scanned_hosts)

    # Run tests.
    results = creds.batch_test_common_credentials(devices)

    # Generate reports.
    if args.json_out:
        json_ = report.generate_json_report(results)
        with open(args.json_out, "w") as f:
            f.write(json_)

    if args.html_out:
        html = report.generate_html_report(results)
        with open(args.html_out, "w") as f:
            f.write(html)


def setup_args():
    """Set up command-line arguments for the script."""
    parser = argparse.ArgumentParser(description="moniot: IoT vulnerability scanner")
    parser.add_argument("network", help="CIDR network range (e.g. 192.168.1.0/24)")

    parser.add_argument(
        "--intrusive",
        action="store_true",
        help="Enable brute-force and other intrusive tests",
    )

    parser.add_argument(
        "--json", dest="json_out", default=None, help="Write JSON report to file"
    )

    parser.add_argument(
        "--html", dest="html_out", default=None, help="Write HTML report to file"
    )

    parser.add_argument(
        "--zap-api-key",
        dest="zap_api_key",
        default=None,
        help="OWASP ZAP API key for ecosystem interface scans",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()

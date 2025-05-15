#!/usr/bin/env python3

import argparse

import creds
import discovery
import report
import webapp


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover and parse devices.
    scanned_hosts = discovery.discover_devices(args.network)
    devices = discovery.parse_device_info(scanned_hosts)

    # Run tests.
    common_creds = creds.batch_test_common_credentials(devices)

    # Scan for web application vulnerabilities.
    # TODO: Exclude zaproxy from itself?
    http_devices = [
        d for d in devices if any(p.service in ["http", "https"] for p in d.open_ports)
    ]

    zap_alerts = webapp.scan_web_apps(
        http_devices, args.zap_api_key, args.local_zap_proxy
    )

    # Merge the common crdential results with the ZAP alerts.
    merged_results = {}
    for device, cred_findings in common_creds.items():
        merged_results[device] = {
            "credentials": cred_findings,
            "zap_alerts": zap_alerts.get(device, []),
        }

    # Generate reports.
    if args.json_out:
        json_ = report.generate_json_report(merged_results)
        with open(args.json_out, "w") as f:
            f.write(json_)

    if args.html_out:
        html = report.generate_html_report(merged_results)
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

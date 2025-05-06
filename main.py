#!/usr/bin/env python3
"""
moniot.py: Monitor IoT devices for OWASP IoT Top 10 vulnerabilities.
"""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap
from jinja2 import Environment, FileSystemLoader
import csv

RES_DIR = "./res"
COMMON_CREDENTIALS = f"{RES_DIR}/common_credentials.csv"


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover devices.
    hosts = discover_devices(args.network)
    devices = [{"ip": h, "mac": None} for h in hosts]

    # Fingerprint services.
    nm = nmap.PortScanner()
    nm.scan(hosts=args.network, arguments="-sV -O -T4")

    # Define common credentials.
    default_creds = []
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        default_creds = [(row[0], row[1]) for row in reader if len(row) >= 2]

    # Test for vulnerabilities.
    results = []
    with ThreadPoolExecutor(max_workers=20) as exec:
        futures = {exec.submit(lambda d: d, dev): dev for dev in devices}
        for fut in as_completed(futures):
            dev = futures[fut]
            ip = dev["ip"]
            report = {"ip": ip, "mac": dev.get("mac"), "findings": []}
            results.append(report)

    # Output report.
    print(json.dumps(results, indent=2))

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(results, f, indent=2)

    if args.html_out:
        html = generate_html_report(results)
        with open(args.html_out, "w") as f:
            f.write(html)


def discover_devices(net_range):
    """Perform a ping scan on the given network range to discover live hosts."""
    nm = nmap.PortScanner()
    nm.scan(hosts=net_range, arguments="-sn")
    return [h for h in nm.all_hosts() if nm[h].state() == "up"]


def generate_html_report(results, template_dir="templates"):
    """Generate an HTML report from the scan results using Jinja2 templates."""
    env = Environment(loader=FileSystemLoader(template_dir))
    tmpl = env.get_template("report.html.jinja")
    return tmpl.render(devices=results)


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

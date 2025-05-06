#!/usr/bin/env python3
"""
moniot.py: Monitor IoT devices for OWASP IoT Top 10 vulnerabilities.
"""
import argparse
import csv
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum

import nmap
import paramiko
from jinja2 import Environment, FileSystemLoader

RES_DIR = "./res"
COMMON_CREDENTIALS = f"{RES_DIR}/common_credentials.csv"


@dataclass
class Device:
    """Dataclass to hold device information."""

    ip: str
    hostname: str
    os: str
    services: list


@dataclass
class CommonCredentialsFinding:
    """Dataclass to hold common credentials findings."""

    ip: str
    service: "Service"
    username: str
    password: str


class Service(Enum):
    SSH = "SSH"
    HTTP = "HTTP"


def main():
    # Parse command-line arguments.
    args = setup_args()

    # Discover devices.
    hosts = discover_devices(args.network)

    for host in hosts:        
        device = Device(
            ip=host,
            hostname=host.hostname(),
            os=host["osmatch"][0]["name"] if "osmatch" in host else "Unknown",
            services=[(proto, host[proto]) for proto in host.all_protocols()],
        )

        print(f"Discovered device: {device}")

    # Define common credentials.
    default_creds = []
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        default_creds = [(row[0], row[1]) for row in reader if len(row) >= 2]

    # Test for vulnerabilities.
    results = []
    with ThreadPoolExecutor(max_workers=20) as exec:
        futures = {exec.submit(lambda d: d, dev.ip): dev for dev in hosts}

        for fut in as_completed(futures):
            ip = futures[fut]
            report = {"ip": ip, "findings": []}

            # Run the vulnerability tests.
            report["findings"] = test_common_credentials(ip, default_creds)

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
    """Discover devices on the network using nmap and fingerprint them."""
    nm = nmap.PortScanner()
    nm.scan(hosts=net_range, arguments="-sV -O -T4")
    return [nm[host] for host in nm.all_hosts() if nm[host].state() == "up"]


def test_common_credentials(ip, creds, timeout_seconds=5):
    """Test common credentials against a device."""
    findings = []

    # SSH.
    for user, pwd in creds:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=pwd, timeout=timeout_seconds)
            ssh.close()
            findings.append(CommonCredentialsFinding(ip, Service.SSH, user, pwd))
        except Exception:
            continue

    # HTTP.
    for user, pwd in creds:
        try:
            s = requests.Session()
            payload = {"username": user, "password": pwd}
            r = s.post(f"http://{ip}/login", data=payload, timeout=timeout_seconds)
            if r.status_code == 200:
                findings.append(CommonCredentialsFinding(ip, Service.HTTP, user, pwd))
        except Exception:
            continue

    return findings


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

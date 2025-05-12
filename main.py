#!/usr/bin/env python3

import argparse
import csv
from datetime import datetime
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Optional
from enum import Enum

import nmap
import paramiko
from jinja2 import Environment, FileSystemLoader

RES_DIR = "./res"
COMMON_CREDENTIALS = f"{RES_DIR}/common_credentials.csv"
TEMPLATE_DIR = "./templates"
REPORT_TEMPLATE = f"{TEMPLATE_DIR}/report.html.j2"


@dataclass(frozen=True)
class PortInfo:
    port: int
    state: str
    service: str
    product: str
    version: str
    cpe: str


@dataclass(frozen=True)
class OSClass:
    type: str
    vendor: str
    osfamily: str
    osgen: Optional[str]
    accuracy: str
    cpe: list[str]

    def __hash__(self):
        return hash(
            self.type + self.vendor + self.osfamily + str(self.osgen) + self.accuracy
        )


@dataclass(frozen=True)
class OSMatch:
    name: str
    accuracy: str
    osclasses: list[OSClass]

    def __hash__(self):
        return hash(
            self.name + self.accuracy + "".join([str(cls) for cls in self.osclasses])
        )


@dataclass(frozen=True)
class Device:
    ip: str
    hostname: Optional[str]
    status: str
    uptime_seconds: Optional[str]
    last_boot: Optional[str]
    open_ports: tuple[PortInfo, ...] = field(default_factory=tuple)
    os_matches: tuple[OSMatch, ...] = field(default_factory=tuple)

    def __hash__(self):
        return hash(self.ip)


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

    # Discover and parse devices.
    scanned_hosts = discover_devices(args.network)
    devices = parse_device_info(scanned_hosts)

    # Load credentials.
    default_creds = []
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        default_creds = [(row[0], row[1]) for row in reader if len(row) >= 2]

    # Run tests.
    results = run_tests(devices, default_creds)

    if args.json_out:
        json_ = generate_json_report(results)
        print(json_)

        with open(args.json_out, "w") as f:
            f.write(json_)

    if args.html_out:
        html = generate_html_report(results)
        with open(args.html_out, "w") as f:
            f.write(html)


def run_tests(devices, creds):
    """Run vulnerability tests on devices and return structured results."""
    results = {}
    with ThreadPoolExecutor() as pool:
        future_to_device = {
            pool.submit(test_common_credentials, dev.ip, creds): dev for dev in devices
        }

        for fut in as_completed(future_to_device):
            device = future_to_device[fut]
            findings = fut.result()
            results[device] = findings

    return results


def discover_devices(net_range):
    """Discover devices on the network using nmap and fingerprint them."""
    nm = nmap.PortScanner()
    nm.scan(hosts=net_range, arguments="-sV -O -T4")
    return [nm[host] for host in nm.all_hosts() if nm[host].state() == "up"]


def parse_device_info(hosts):
    devices = []

    for host in hosts:
        ip = host.get("addresses", {}).get("ipv4")
        hostname = next(
            (h["name"] for h in host.get("hostnames", []) if h.get("name")), None
        )
        status = host.get("status", {}).get("state", "unknown")
        uptime_seconds = host.get("uptime", {}).get("seconds")
        last_boot = host.get("uptime", {}).get("lastboot")

        # Ports
        open_ports = [
            PortInfo(
                port=port,
                state=details.get("state", ""),
                service=details.get("name", ""),
                product=details.get("product", ""),
                version=details.get("version", ""),
                cpe=details.get("cpe", ""),
            )
            for port, details in host.get("tcp", {}).items()
        ]

        # OS matches
        os_matches = []
        for match in host.get("osmatch", []):
            osclasses = [
                OSClass(
                    type=cls.get("type", ""),
                    vendor=cls.get("vendor", ""),
                    osfamily=cls.get("osfamily", ""),
                    osgen=cls.get("osgen"),
                    accuracy=cls.get("accuracy", ""),
                    cpe=cls.get("cpe", []),
                )
                for cls in match.get("osclass", [])
            ]
            os_matches.append(
                OSMatch(
                    name=match.get("name", ""),
                    accuracy=match.get("accuracy", ""),
                    osclasses=osclasses,
                )
            )
        os_matches = sorted(os_matches, key=lambda m: int(m.accuracy), reverse=True)[:3]

        devices.append(
            Device(
                ip=ip,
                hostname=hostname,
                status=status,
                uptime_seconds=uptime_seconds,
                last_boot=last_boot,
                open_ports=open_ports,
                os_matches=os_matches,
            )
        )

    return devices


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


def generate_json_report(results):
    results_dicts = [
        {**asdict(device), "findings": [asdict(f) for f in findings]}
        for device, findings in results.items()
    ]

    return json.dumps(results_dicts, indent=2)


def generate_html_report(results):
    """Generate an HTML report from the scan results using Jinja2 templates."""
    env = Environment(loader=FileSystemLoader("."), extensions=["jinja2.ext.do"])
    tmpl = env.get_template(REPORT_TEMPLATE)
    return tmpl.render(
        devices=results, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


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

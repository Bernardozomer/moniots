from typing import TYPE_CHECKING

import nmap

import models

if TYPE_CHECKING:
    from nmap import PortScannerHostDict


def discover_devices(net_range: str) -> list["PortScannerHostDict"]:
    """Discover devices on the network using nmap and fingerprint them."""
    nm = nmap.PortScanner()
    nm.scan(hosts=net_range, arguments="-sV -O -T4 --script vulners")
    return [nm[host] for host in nm.all_hosts() if nm[host].state() == "up"]


def parse_device_info(
    hosts: list["PortScannerHostDict"],
) -> dict[models.Device, list[models.VulnersAlert]]:
    """Parse device information from nmap scan results."""
    devices = {}

    for host in hosts:
        ip = host.get("addresses", {}).get("ipv4")
        hostname = next(
            (h["name"] for h in host.get("hostnames", []) if h.get("name")), None
        )
        status = host.get("status", {}).get("state", "unknown")
        uptime_seconds = host.get("uptime", {}).get("seconds")
        last_boot = host.get("uptime", {}).get("lastboot")

        # Parse OS matches.
        os_matches: list[models.OSMatch] = []
        for match in host.get("osmatch", []):
            osclasses = [
                models.OSClass(
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
                models.OSMatch(
                    name=match.get("name", ""),
                    accuracy=match.get("accuracy", ""),
                    osclasses=osclasses,
                )
            )

        # Sort OS matches by accuracy and limit to top 3.
        os_matches = sorted(os_matches, key=lambda m: int(m.accuracy), reverse=True)[:3]

        # Parse open ports and vulners alerts.
        open_ports = []
        vulners_alerts = []

        for port, details in host.get("tcp", {}).items():
            open_ports.append(
                models.PortInfo(
                    port=port,
                    state=details.get("state", ""),
                    service=details.get("name", ""),
                    product=details.get("product", ""),
                    version=details.get("version", ""),
                    cpe=details.get("cpe", ""),
                )
            )

            # Check for vulners script output.
            if "script" in details and "vulners" in details["script"]:
                # Separate each line and skip cpe repeated at the start.
                vulners_data: list[str] = details["script"]["vulners"].split("\n")[1:]
                cpe: str = vulners_data.pop(0)

                for alert in vulners_data:
                    alert = alert.split()

                    vulners_alerts.append(
                        models.VulnersAlert(
                            source=models.AlertSource.VULNERS,
                            severity=models.Severity.from_cvss(float(alert[1])),
                            title=alert[0],
                            description=None,  # No description provided in nmap output
                            cwe_ids=None,
                            cve_ids=[alert[0]] if alert[0].startswith("CVE-") else None,
                            remediation=None,  # No remediation provided in nmap output
                            port=int(port),
                            cpe=cpe,
                            exploit_id=alert[0] if len(alert) == 4 else None,
                            cvss=float(alert[1]),
                            url=alert[2],
                        )
                    )

        # Create device model instance.
        device = models.Device(
            ip=ip,
            hostname=hostname,
            status=status,
            uptime_seconds=uptime_seconds,
            last_boot=last_boot,
            open_ports=tuple(open_ports),
            os_matches=tuple(os_matches),
        )

        devices[device] = vulners_alerts

    return devices

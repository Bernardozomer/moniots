import nmap

import models


def discover_devices(net_range):
    """Discover devices on the network using nmap and fingerprint them."""
    nm = nmap.PortScanner()
    nm.scan(hosts=net_range, arguments="-sV -O -T4")
    return [nm[host] for host in nm.all_hosts() if nm[host].state() == "up"]


def parse_device_info(hosts):
    """Parse device information from nmap scan results."""
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
            models.PortInfo(
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
        os_matches = sorted(os_matches, key=lambda m: int(m.accuracy), reverse=True)[:3]

        devices.append(
            models.Device(
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

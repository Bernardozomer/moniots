import time
from typing import Callable

from zapv2 import ZAPv2

import models


def run_zap(
    devices: list[models.Device],
    zap_api_key: str,
    local_zap_proxy: str,
) -> dict[models.Device, list[models.ZAPAlert]]:
    """Scan web applications for vulnerabilities using OWASP ZAP."""
    proxies = {"http": local_zap_proxy, "https": local_zap_proxy}
    zap = ZAPv2(apikey=zap_api_key, proxies=proxies)
    zap.pscan.enable_all_scanners()
    alerts = {}

    for device in devices:
        ip = device.ip
        print(f"Scanning {ip}...")
        session_name = f"moniots_{ip}"
        zap.core.new_session(session_name, overwrite=True)
        url = "http://" + ip
        zap.core.access_url(url, followredirects=True)
        # Give the sites tree a chance to update.
        _sleep()

        # Perform the spider scan.
        _run_scan(zap.spider.scan, zap.spider.status, url, recurse=True)
        # Perform the active scan.
        _run_scan(zap.ascan.scan, zap.ascan.status, url, recurse=True, postdata=True)

        # Parse and store results.
        alerts[device] = _parse_zap_alerts(zap.core.alerts(baseurl=url))

    return alerts


def _run_scan(scan_func: Callable, status_func: Callable, url: str, **kwargs):
    """Run a ZAP scan and monitor its progress."""
    scan_id = scan_func(url, **kwargs)
    # Give the scanner a chance to start.
    _sleep()

    while (progress := int(status_func(scan_id))) < 100:
        # TODO: Replace with a progress bar.
        print(f"Scan progress: {progress}%")
        _sleep()


def _parse_zap_alerts(zap_alerts: list[dict]) -> list[models.ZAPAlert]:
    """Parse ZAP alerts for processing."""
    return [
        models.ZAPAlert(
            source=models.AlertSource.ZAP,
            severity=models.Severity.from_label(a["risk"]),
            title=a.get("name", "Untitled"),
            description=a.get("description", "No description"),
            cwe_ids=[a["cweid"]],
            cve_ids=None,
            remediation=a.get("solution", None),
            url=a["url"] or a["uri"],
            method=a["method"],
            parameter=a.get("param"),
            evidence=a.get("evidence"),
            confidence=models.Confidence(a["confidence"]),
        )
        for a in zap_alerts
    ]


def _sleep(seconds: int = 2):
    """Sleep for a given time in seconds."""
    time.sleep(seconds)

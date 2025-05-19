import time

from zapv2 import ZAPv2

import models


def scan_web_apps(devices, zap_api_key, local_zap_proxy):
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
        sleep()

        # Perform the spider scan.
        run_scan(zap.spider.scan, zap.spider.status, url, recurse=True)
        # Perform the active scan.
        run_scan(zap.ascan.scan, zap.ascan.status, url, recurse=True, postdata=True)

        # Parse and store results.
        alerts[device] = parse_zap_alerts(zap.core.alerts(baseurl=url))

    return alerts


def run_scan(scan_func, status_func, url, **kwargs):
    scan_id = scan_func(url, **kwargs)
    # Give the scanner a chance to start.
    sleep()

    while (progress := int(status_func(scan_id))) < 100:
        # TODO: Replace with a progress bar.
        print(f"Scan progress: {progress}%")
        sleep()


def parse_zap_alerts(zap_alerts):
    """Parse ZAP alerts for processing."""
    return [
        models.ZAPAlert(
            source=models.AlertSource.ZAP,
            severity=models.Severity(a["risk"]),
            title=a.get("name", "Untitled"),
            description=a.get("description", "No description"),
            cwe_id=a["cweid"],
            remediation=a.get("solution", None),
            url=a["url"] or a["uri"],
            method=a["method"],
            parameter=a.get("param"),
            evidence=a.get("evidence"),
            confidence=models.Confidence(a["confidence"]),
        )
        for a in zap_alerts
    ]


def sleep(seconds=2):
    """Sleep for a given time in seconds."""
    time.sleep(seconds)

import argparse

from . import exploitdb, creds, discovery, insecure_srv, models, nvd, zap


def orchestrate_scan(
    args: argparse.Namespace,
) -> dict[models.Device, list[models.Alert]]:
    """Orchestrates the device discovery and vulnerability scanning process.
    This function is intended to be called by different interfaces (CLI, Web UI).
    """
    # Discover and parse devices.
    print(f"Scanning {args.network}")
    scanned_hosts = discovery.discover_devices(args.network)
    devices = discovery.parse_device_info(scanned_hosts)
    print(f"Discovered {len(devices)} devices.")

    if not devices:
        return {}

    # Run tests and return.
    return run_tests(args, devices)


def run_tests(
    args: argparse.Namespace, devices: list[models.Device]
) -> dict[models.Device, list[models.Alert]]:
    """Run vulnerability tests on devices and return structured results."""
    # Test for common credentials.
    cred_alerts = creds.batch_test_common_credentials(devices)
    # Test for insecure services.
    insecure_srv_alerts = insecure_srv.batch_test_insecure_services(devices)
    # Scan for product exploits.
    exploitdb_alerts = exploitdb.batch_query_exploitdb(devices)
    # Query NVD for CVEs.
    nvd_alerts = nvd.batch_query_nvd(devices, nvd_api_key=args.nvd_api_key)

    # Scan for web application vulnerabilities.
    # Filter devices to only those with HTTP/HTTPS services.
    http_devices = [
        d
        for d in devices
        if any(p.service.lower() in ["http", "https"] for p in d.open_ports)
    ]

    zap_alerts = {}
    if http_devices:
        zap_alerts = zap.run_zap(
            http_devices,
            args.zap_api_key,
            args.local_zap_proxy,
        )

    # Merge alert results.
    alerts = merge_alerts(
        devices,
        cred_alerts,
        insecure_srv_alerts,
        zap_alerts,
        exploitdb_alerts,
        nvd_alerts,
    )

    # Filter alerts by severity and return.
    min_severity = models.Severity.from_label(args.severity)
    return {d: [a for a in alerts[d] if a.severity >= min_severity] for d in alerts}


def merge_alerts(devices: list[models.Device], *alert_dicts):
    """Merge alerts from multiple sources for each device."""
    merge = lambda device: [
        alert for source in alert_dicts for alert in source.get(device, [])
    ]

    return {device: merge(device) for device in devices}

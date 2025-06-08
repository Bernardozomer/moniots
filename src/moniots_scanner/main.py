import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import exploitdb, creds, discovery, insecure_srv, models, nvd, util, zap


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
    """
    Runs vulnerability tests on devices using a centralized worker pool.
    It creates a queue of granular (device, test_function) tasks and
    processes them concurrently to optimize I/O-bound operations.
    """
    # Final dictionary to aggregate all alerts, initialized for each device.
    all_alerts: dict[models.Device, list[models.Alert]] = {
        device: [] for device in devices
    }

    # Load resources once to avoid repeated file I/O within tasks.
    try:
        common_creds_list = creds.load_cred_data()
    except FileNotFoundError:
        print("Warning: Common credentials file not found. Skipping credentials test.")
        common_creds_list = []

    try:
        insecure_services_data = insecure_srv.load_service_data()
    except FileNotFoundError:
        print("Warning: Insecure services file not found. Skipping services test.")
        insecure_services_data = {}

    # This map will hold the context (device, task_type) for each future.
    futures = {}
    zap_future = None

    with ThreadPoolExecutor() as executor:
        # Enqueue all per-device tasks.
        print(f"Enqueuing tasks for {len(devices)} devices...")
        for device in devices:
            # Enqueue common credentials test.
            if common_creds_list:
                future = executor.submit(
                    creds.test_common_credentials, device, common_creds_list
                )
                futures[future] = device

            # Enqueue insecure services test.
            if insecure_services_data:
                future = executor.submit(
                    insecure_srv.test_insecure_services,
                    device,
                    insecure_services_data,
                )
                futures[future] = device

            # Enqueue ExploitDB query.
            future = executor.submit(exploitdb.query_exploitdb, device)
            futures[future] = device

            # Enqueue NVD query.
            future = executor.submit(nvd.query_nvd, device, args.nvd_api_key)
            futures[future] = device

        # Enqueue the ZAP scan as a single, separate task.
        # ZAP works on a batch of devices, so it's treated differently.
        http_devices = [
            d
            for d in devices
            if any(p.service.lower() in ["http", "https"] for p in d.open_ports)
        ]

        if http_devices:
            print("Enqueuing ZAP web application scan.")
            zap_future = executor.submit(
                zap.run_zap, http_devices, args.zap_api_key, args.local_zap_proxy
            )

        # Process results as they complete.
        print(f"Processing {len(futures)} per-device tasks...")
        for future in util.pbar(
            as_completed(futures),
            desc="Scanning devices",
            total=len(futures),
        ):
            device = futures[future]
            try:
                # result is a list of alerts for a single device
                result_alerts = future.result()
                if result_alerts:
                    all_alerts[device].extend(result_alerts)
            except Exception as e:
                print(f"Error scanning device {device.ip}: {e}")

        # Process the ZAP scan result after it's done.
        if zap_future:
            print("Waiting for ZAP scan to complete...")
            try:
                zap_results = zap_future.result()
                for device, alerts in zap_results.items():
                    if alerts:
                        all_alerts[device].extend(alerts)
                print("ZAP scan results merged.")
            except Exception as e:
                print(f"ZAP scan failed: {e}")

    # Filter final results based on minimum severity.
    min_severity = models.Severity.from_label(args.severity)

    filtered_alerts = {}
    for device, alerts in all_alerts.items():
        # Keep alerts that meet or exceed the minimum severity
        passing_alerts = [a for a in alerts if a.severity >= min_severity]
        filtered_alerts[device] = passing_alerts

    return filtered_alerts


def merge_alerts(devices: list[models.Device], *alert_dicts):
    """Merge alerts from multiple sources for each device."""
    merge = lambda device: [
        alert for source in alert_dicts for alert in source.get(device, [])
    ]

    return {device: merge(device) for device in devices}

import csv
import paramiko
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import models

COMMON_CREDENTIALS = f"{models.RES_DIR}/common_credentials.csv"


def batch_test_common_credentials(
    devices: list[models.Device],
) -> dict[models.Device, list[models.CommonCredentialsAlert]]:
    """Run vulnerability tests on devices and return structured results."""
    # Load credentials.
    creds = []
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        creds = [(row[0], row[1]) for row in reader if len(row) >= 2]

    # Attempt to connect to each device with each set of common credentials.
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


def test_common_credentials(
    ip: str, creds: list[tuple[str, str]], timeout_seconds: int = 5
):
    """Attempt to connect to a device with multiple sets of common credentials."""
    alerts = []

    def check_and_alert(service: str, connect_func: Callable[[str, str], bool]):
        """Check device credentials and create alerts if common credentials are found."""
        for user, pwd in creds:
            try:
                if connect_func(user, pwd):
                    alerts.append(
                        models.CommonCredentialsAlert(
                            source=models.AlertSource.CREDS,
                            severity=models.Severity.CRITICAL,
                            title=f"Common {service} Credentials",
                            description=f"Device is using easily guessable {service} credentials.",
                            cwe_ids=[521, 798, 1392],
                            cve_ids=None,
                            remediation="Change device credentials.",
                            service=service,
                            username=user,
                            password=pwd,
                        )
                    )
            except Exception:
                continue

    def ssh_connect(user: str, pwd: str) -> bool:
        """Attempt to connect via SSH with given credentials."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd, timeout=timeout_seconds)
        ssh.close()
        return True

    def http_connect(user: str, pwd: str) -> bool:
        """Attempt to connect via HTTP with given credentials."""
        s = requests.Session()
        payload = {"username": user, "password": pwd}
        r = s.post(f"http://{ip}/login", data=payload, timeout=timeout_seconds)
        return r.status_code == 200

    # Run checks for all services.
    check_and_alert("ssh", ssh_connect)
    check_and_alert("http", http_connect)

    return alerts

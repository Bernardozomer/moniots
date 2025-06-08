import csv
import paramiko
import requests
from typing import Callable

from . import models, util

COMMON_CREDENTIALS = f"{util.RES_DIR}/common_credentials.csv"


def test_common_credentials(
    device: models.Device, creds: list[tuple[str, str]], timeout_seconds: int = 5
) -> list[models.CommonCredentialsAlert]:
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
        ssh.connect(device.ip, username=user, password=pwd, timeout=timeout_seconds)
        ssh.close()
        return True

    def http_connect(user: str, pwd: str) -> bool:
        """Attempt to connect via HTTP with given credentials."""
        s = requests.Session()
        payload = {"username": user, "password": pwd}
        r = s.post(f"http://{device.ip}/login", data=payload, timeout=timeout_seconds)
        return r.status_code == 200

    # Run checks for all services.
    check_and_alert("ssh", ssh_connect)
    check_and_alert("http", http_connect)

    return alerts


def load_cred_data() -> list[tuple[str, str]]:
    """Load insecure services from a YAML file."""
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        return [(row[0], row[1]) for row in reader if len(row) >= 2]

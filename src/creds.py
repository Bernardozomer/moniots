import csv
import paramiko
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

import models

RES_DIR = "./res"
COMMON_CREDENTIALS = f"{RES_DIR}/common_credentials.csv"


def batch_test_common_credentials(devices):
    """Run vulnerability tests on devices and return structured results."""
    # Load credentials.
    creds = []
    with open(COMMON_CREDENTIALS, "r") as fp:
        reader = csv.reader(fp)
        creds = [(row[0], row[1]) for row in reader if len(row) >= 2]

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


def test_common_credentials(ip, creds, timeout_seconds=5):
    """Test common credentials against a device."""
    alerts = []

    def check_and_alert(service, connect_func):
        for user, pwd in creds:
            try:
                if connect_func(user, pwd):
                    alerts.append(
                        models.CommonCredentialsAlert(
                            source=models.AlertSource.CREDENTIALS,
                            severity=models.Severity.HIGH,
                            title=f"Common {service} Credentials",
                            description=f"Device is using easily guessable {service} credentials.",
                            cwe_ids=[521, 798, 1392],
                            cve_ids=None,
                            remediation="Change device credentials.",
                            service=getattr(models.Service, service),
                            username=user,
                            password=pwd,
                        )
                    )
            except Exception:
                continue

    def ssh_connect(user, pwd):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd, timeout=timeout_seconds)
        ssh.close()
        return True

    def http_connect(user, pwd):
        s = requests.Session()
        payload = {"username": user, "password": pwd}
        r = s.post(f"http://{ip}/login", data=payload, timeout=timeout_seconds)
        return r.status_code == 200

    check_and_alert("SSH", ssh_connect)
    check_and_alert("HTTP", http_connect)

    return alerts

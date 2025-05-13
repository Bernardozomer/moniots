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
    findings = []

    # SSH.
    for user, pwd in creds:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=pwd, timeout=timeout_seconds)
            ssh.close()
            findings.append(
                models.CommonCredentialsFinding(ip, models.Service.SSH, user, pwd)
            )
        except Exception:
            continue

    # HTTP.
    for user, pwd in creds:
        try:
            s = requests.Session()
            payload = {"username": user, "password": pwd}
            r = s.post(f"http://{ip}/login", data=payload, timeout=timeout_seconds)
            if r.status_code == 200:
                findings.append(
                    models.CommonCredentialsFinding(ip, models.Service.HTTP, user, pwd)
                )
        except Exception:
            continue

    return findings

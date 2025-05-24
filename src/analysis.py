import subprocess
import json
from typing import List, Dict

from models import AlertSource, Device, ExploitDBAlert, Severity


def _run_searchsploit(query: str) -> List[Dict]:
    """
    Run `searchsploit -j <query>` and return the parsed JSON dict.
    If searchsploit isn't installed or fails, returns [].
    """
    try:
        proc = subprocess.run(
            ["searchsploit", "-j", query], capture_output=True, text=True, check=True
        )
        data = json.loads(proc.stdout)
        return data.get("RESULTS_EXPLOIT", [])
    except Exception:
        return []


def find_exploits_for_device(device: Device) -> List[ExploitDBAlert]:
    """
    For each open port/service on `device`, call searchsploit and
    collect any matching exploits.
    """
    alerts: List[ExploitDBAlert] = []

    for port in device.open_ports:
        if not port.product:
            # Skip if we don't have a product string.
            continue

        q = f"{port.product} {port.version}".strip()
        results = _run_searchsploit(q)

        for r in results:
            alerts.append(
                ExploitDBAlert(
                    source=AlertSource.EXPLOITDB,
                    severity=Severity.HIGH,  # TODO get from CVEs
                    title=r["Title"],
                    description=None,
                    cwe_ids=[],
                    cve_ids=[c for c in r["Codes"].split(";") if c.startswith("CVE-")],
                    remediation=None,
                    edb_id=r.get("EDB-ID", ""),
                    verified=True if r["Verified"] == 1 else False,
                    port=port.port,
                    type=r["Type"],
                    platform=r["Platform"],
                    author=r["Author"],
                    date=r["Date_Published"],
                    edb_source=r["Source"],
                )
            )

    return alerts


def batch_searchsploit(devices: List[Device]) -> Dict[Device, List[ExploitDBAlert]]:
    """
    Run find_exploits_for_device in parallel over all devices.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    out: Dict[Device, List[ExploitDBAlert]] = {}
    with ThreadPoolExecutor() as pool:
        futures = {pool.submit(find_exploits_for_device, d): d for d in devices}
        for fut in as_completed(futures):
            dev = futures[fut]
            out[dev] = fut.result()
    return out

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
    findings: List[ExploitDBAlert] = []
    for port in device.open_ports:
        # Only query if we have a product string.
        if port.product:
            q = f"{port.product} {port.version}".strip()
            results = _run_searchsploit(q)
            for r in results:
                findings.append(
                    ExploitDBAlert(
                        source=AlertSource.EXPLOITDB,
                        severity=Severity.HIGH,
                        title=r.get("Title", ""),
                        description=r.get("Type", ""),
                        cwe_id=0,
                        remediation="",
                        port=port.port,
                        edb_id=r.get("EDB-ID", ""),
                        date=r.get("Date", ""),
                        author=r.get("Author", ""),
                        file_url=r.get("URL", ""),
                    )
                )
    return findings


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

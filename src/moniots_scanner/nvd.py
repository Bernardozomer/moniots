from typing import Optional

# NOTE: The type checker may not understand nvdlib's dynamic attributes,
# so we use `# type: ignore` to suppress type errors.
import nvdlib

from . import models

# Minimum delay between API calls to avoid rate limiting.
MIN_API_DELAY = 0.6


def query_nvd(
    device: models.Device, nvd_api_key: Optional[str] = None
) -> list[models.NVDAlert]:
    """For each open port/service on `device`, call nvdlib and
    collect any matching CVEs.
    """
    alerts = []

    for port in device.open_ports:
        if not port.cpe:
            # Skip if there is no CPE string.
            continue

        # Ensure CPE is in the correct "cpe:2.3:" format for the API
        cpe_name = port.cpe
        if cpe_name.startswith("cpe:/"):
            # Convert old-style CPE to CPE 2.3 format
            parts = cpe_name[5:].split(":")
            # Pad to at least 7 components (part, vendor, product, version, update, edition, language)
            parts += ["*"] * (7 - len(parts))
            cpe_name = "cpe:2.3:" + ":".join(parts)

        results = nvdlib.searchCVE(
            cpeName=cpe_name, key=nvd_api_key, delay=MIN_API_DELAY
        )

        for r in results:
            severity = models.Severity.from_cvss(r.score[1])  # type: ignore

            description = next(
                (l.value for l in r.descriptions if l.lang == "en"), None  # type: ignore
            )

            cwe_ids = {
                int(cwe_obj.value)
                for cwe_obj in r.cwe
                if cwe_obj.lang == "en" and str(cwe_obj.value).isdigit()
            }

            remediation = getattr(r, "requiredAction", None)

            alerts.append(
                models.NVDAlert(
                    source=models.AlertSource.NVD,
                    severity=severity,
                    title=f"{port.product} - {r.id}",  # type: ignore
                    description=description,
                    cwe_ids=list(cwe_ids),
                    cve_ids=[r.id],  # type: ignore
                    remediation=remediation,
                    cpe=port.cpe,
                    nvd_source=r.sourceIdentifier,  # type: ignore
                    date=r.published,  # type: ignore
                    url=r.url,
                )
            )

    return alerts


def get_cve_severity(cve_id: str, nvd_api_key: Optional[str] = None) -> models.Severity:
    """Get the severity of a CVE from the NVD."""
    cve = nvdlib.searchCVE(cveId=cve_id, key=nvd_api_key)[0]
    return models.Severity.from_cvss(cve.score[1])  # type: ignore

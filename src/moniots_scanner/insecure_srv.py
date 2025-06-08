import yaml

from . import models, util

# NOTE: The type checker may not understand YAML's dynamic attributes,
# so we use `# type: ignore` to suppress type errors.
INSECURE_SERVICES = f"{util.RES_DIR}/insecure_services.yml"


def test_insecure_services(
    device: models.Device, services: dict[str, dict[str, str]]
) -> list[models.InsecureServiceAlert]:
    """Check device for insecure services."""
    alerts = []

    for port_info in device.open_ports:
        service_name = port_info.service.lower()

        service = services.get(service_name)
        if not service:
            continue

        # Find the first matching port entry (by port or wildcard).
        match = next(
            (
                entry
                for entry in service["ports"]
                if entry["port"] == port_info.port or entry["port"] == -1  # type: ignore
            ),
            None,
        )

        if not match:
            continue

        description = f"{service["description"]} {match["note"]}"  # type: ignore

        alerts.append(
            models.InsecureServiceAlert(
                source=models.AlertSource.INSECURE_SRV,
                severity=models.Severity[service["severity"]],
                title=f"Insecure service: {service_name}",
                description=description,
                cwe_ids=service["cwe_ids"],  # type: ignore
                cve_ids=None,
                remediation=service["remediation"],
            )
        )

    return alerts


def load_service_data() -> dict[str, dict]:
    """Load insecure services from a YAML file."""
    yaml.SafeDumper.ignore_aliases = lambda *_, **__: True

    with open(INSECURE_SERVICES, "r") as file:
        data = yaml.safe_load(file)["services"]

    # Skip YAML aliases ("services" without a "name" key).
    return {s["name"]: s for s in data if "name" in s}

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


@dataclass(frozen=True)
class PortInfo:
    port: int
    state: str
    service: str
    product: str
    version: str
    cpe: str


@dataclass(frozen=True)
class OSClass:
    type: str
    vendor: str
    osfamily: str
    osgen: Optional[str]
    accuracy: str
    cpe: list[str]

    def __hash__(self):
        return hash(
            self.type + self.vendor + self.osfamily + str(self.osgen) + self.accuracy
        )


@dataclass(frozen=True)
class OSMatch:
    name: str
    accuracy: str
    osclasses: list[OSClass]

    def __hash__(self):
        return hash(
            self.name + self.accuracy + "".join([str(cls) for cls in self.osclasses])
        )


@dataclass(frozen=True)
class Device:
    ip: str
    hostname: Optional[str]
    status: str
    uptime_seconds: Optional[str]
    last_boot: Optional[str]
    open_ports: tuple[PortInfo, ...] = field(default_factory=tuple)
    os_matches: tuple[OSMatch, ...] = field(default_factory=tuple)

    def __hash__(self):
        return hash(self.ip)


@dataclass
class CommonCredentialsFinding:
    """Dataclass to hold common credentials findings."""

    ip: str
    service: "Service"
    username: str
    password: str


class Service(Enum):
    SSH = "SSH"
    HTTP = "HTTP"


@dataclass(frozen=True)
class ZAPAlert:
    alert: str
    risk: str
    confidence: str
    cwe: str
    wasc: str
    url: str
    parameter: Optional[str]
    method: Optional[str]
    evidence: Optional[str]
    description: Optional[str]
    solution: Optional[str]

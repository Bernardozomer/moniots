from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
class PortInfo:
    port: int
    state: str
    service: str
    product: str
    version: str
    cpe: str


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


class Severity(Enum):
    INFO = ("Informational", 0.0)
    LOW = ("Low", 0.1)
    MEDIUM = ("Medium", 4.0)
    HIGH = ("High", 7.0)
    CRITICAL = ("Critical", 9.0)

    @property
    def label(self) -> str:
        return self.value[0]

    @property
    def min_cvss(self) -> float:
        return self.value[1]

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        """Get Severity from its label."""
        for sev in cls:
            if sev.label.lower() == label.lower():
                return sev
        raise ValueError(f"Unknown severity label: {label}")

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        for sev in reversed(cls):
            if score >= sev.min_cvss:
                return sev
        return cls.INFO

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return list(type(self)).index(self) < list(type(self)).index(other)

    def __le__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return list(type(self)).index(self) <= list(type(self)).index(other)

    def __gt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return list(type(self)).index(self) > list(type(self)).index(other)

    def __ge__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return list(type(self)).index(self) >= list(type(self)).index(other)


class AlertSource(str, Enum):
    CREDS = "Moniots Creds"
    INSECURE_SRV = "Moniots Services"
    ZAP = "ZAP"
    EXPLOITDB = "ExploitDB"
    NVD = "NVD"


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class Alert:
    source: AlertSource
    severity: Severity
    title: str
    description: Optional[str]
    cwe_ids: Optional[list[int]]
    cve_ids: Optional[list[str]]
    remediation: Optional[str]


@dataclass
class CommonCredentialsAlert(Alert):
    service: str
    username: str
    password: str


@dataclass
class ZAPAlert(Alert):
    url: str
    method: str
    parameter: Optional[str]
    evidence: Optional[str]
    confidence: Confidence


@dataclass
class ExploitDBAlert(Alert):
    edb_id: str
    verified: bool
    port: int
    type: str
    platform: str
    author: str
    date: str
    edb_source: str


@dataclass
class NVDAlert(Alert):
    cpe: str
    nvd_source: str
    date: str
    url: str


@dataclass
class InsecureServiceAlert(Alert):
    pass

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


class Service(Enum):
    SSH = "SSH"
    HTTP = "HTTP"


class Severity(Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

    @classmethod
    def from_cvss(cls, cvss_score: float) -> "Severity":
        """Return the Severity level based on a CVSS score."""
        if cvss_score < 0.1:
            return cls.INFO
        elif cvss_score < 4.0:
            return cls.LOW
        elif cvss_score < 7.0:
            return cls.MEDIUM
        else:
            return cls.HIGH

    def to_min_cvss(self) -> float:
        """Return the minimum CVSS score for this severity level."""
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 0.1,
            Severity.MEDIUM: 4.0,
            Severity.HIGH: 7.0,
        }[self]

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return order.index(self) <= order.index(other)

    def __gt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return order.index(self) > order.index(other)

    def __ge__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return order.index(self) >= order.index(other)


class AlertSource(Enum):
    CREDENTIALS = "Moniots"
    ZAP = "OWASP Zap"
    EXPLOITDB = "ExploitDB"
    VULNERS = "Vulners"


class Confidence(Enum):
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
    service: Service
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
class VulnersAlert(Alert):
    port: int
    cpe: str
    exploit_id: Optional[str]
    cvss: float
    url: str

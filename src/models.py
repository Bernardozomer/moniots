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


class Confidence(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class Alert:
    source: AlertSource
    severity: Severity
    title: str
    description: str
    cwe_id: int
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
    port: int
    edb_id: str
    date: str
    author: str
    file_url: Optional[str]

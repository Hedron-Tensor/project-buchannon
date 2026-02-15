from dataclasses import dataclass, field


@dataclass
class ThreatResult:
    safe: bool
    level: str = "none"
    module: str = ""
    description: str = ""
    matched_rule: str = ""


@dataclass
class ScanReport:
    module: str
    files_scanned: int = 0
    threats: list = field(default_factory=list)

    @property
    def clean(self):
        return len(self.threats) == 0

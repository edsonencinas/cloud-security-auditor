from dataclasses import dataclass, asdict, field
@dataclass
class Finding:
    check_id: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    resource_type: str
    resource: str
    description: str
    recommendation: str
    remediable: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

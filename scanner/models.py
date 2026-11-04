from dataclasses import dataclass, asdict


@dataclass
class Finding:
    rule_id: str
    severity: str  # "high", "medium", "low"
    resource: str  # id or name of the thing that failed the check
    message: str
    fix: str  # plain English suggested fix
    kind: str = "security"  # "security", "waste", "drift"
    monthly_usd: float = 0.0  # rough monthly waste this finding represents, 0 when not estimated

    def to_dict(self):
        return asdict(self)

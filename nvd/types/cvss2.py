from dataclasses import dataclass


@dataclass()
class CVSS2:
    access_complexity: str
    access_vector: str
    authentication: str
    availability_impact: str
    availability_requirement: str
    base_score: float
    collateral_damage_potential: str
    confidentiality_impact: str
    confidentiality_requirement: str
    environmental_score: float
    exploitability: str
    integrity_impact: str
    integrity_requirement: str
    remediation_level: str
    report_confidence: str
    target_distribution: str
    temporal_score: float
    vector_string: str
    version: str

    @property
    def vector(self) -> str:
        return self.vector_string


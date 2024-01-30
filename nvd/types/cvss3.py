from dataclasses import dataclass


@dataclass()
class CVSS3:
    attack_complexity: str
    attack_vector: str
    availability_impact: str
    availability_requirement: str
    base_score: float
    base_severity: str
    confidentiality_impact: str
    confidentiality_requirement: str
    environmental_score: float
    environmental_severity: str
    exploit_code_maturity: str
    integrity_impact: str
    integrity_requirement: str
    modified_attack_complexity: str
    modified_attack_vector: str
    modified_availability_impact: str
    modified_confidentiality_impact: str
    modified_integrity_impact: str
    modified_privileges_required: str
    modified_user_interaction: str
    privileges_required: str
    remediation_level: str
    report_confidence: str
    scope: str
    temporal_score: float
    temporal_severity: str
    user_interaction: str
    vector_string: str
    version: str

    @property
    def vector(self) -> str:
        return self.vector_string

from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class MitreTechniqueRead(BaseModel):
    """Pydantic model representing an individual MITRE ATT&CK technique."""

    id: str = Field(..., description="MITRE Technique ID (e.g., T1110.001)")
    name: str = Field(..., description="Technique name (e.g., Password Guessing)")
    tactic: str = Field(..., description="Primary MITRE ATT&CK tactic category")
    tactics: List[str] = Field(
        default_factory=list,
        description="All applicable MITRE ATT&CK tactics for this technique",
    )
    description: str = Field(
        ..., description="Description of the adversary technique"
    )
    data_sources: List[str] = Field(
        default_factory=list,
        description="Telemetry log sources that detect this technique",
    )
    detection_rules: List[str] = Field(
        default_factory=list,
        description="Platform detection rule IDs that map to this technique",
    )
    is_known: bool = Field(
        True,
        description="Whether this technique is officially cataloged in the taxonomy",
    )

    model_config = ConfigDict(from_attributes=True)


class MitreTacticRead(BaseModel):
    """Pydantic model representing a MITRE ATT&CK tactic category with mapped techniques."""

    id: str = Field(..., description="MITRE Tactic ID (e.g., TA0001)")
    name: str = Field(..., description="Tactic name (e.g., Initial Access)")
    description: str = Field(..., description="Description of the tactic objective")
    techniques: List[MitreTechniqueRead] = Field(
        default_factory=list,
        description="Techniques associated with this tactic",
    )

    model_config = ConfigDict(from_attributes=True)


class MitreEnrichmentRead(BaseModel):
    """Pydantic model for security event/alert MITRE enrichment context."""

    technique_id: str = Field(..., description="MITRE Technique ID")
    technique_name: str = Field(..., description="Technique name")
    tactic: str = Field(..., description="Primary tactic")
    tactics: List[str] = Field(
        default_factory=list, description="All associated tactics"
    )
    data_sources: List[str] = Field(
        default_factory=list, description="Relevant data sources"
    )
    severity_hint: Optional[str] = Field(
        None, description="Suggested baseline severity for this technique"
    )
    detection_rules: List[str] = Field(
        default_factory=list, description="Detection rule IDs targeting this technique"
    )
    is_known: bool = Field(
        True, description="Whether this technique was resolved from known taxonomy"
    )

    model_config = ConfigDict(from_attributes=True)

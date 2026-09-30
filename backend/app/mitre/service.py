"""Service for MITRE ATT&CK for Cloud lookup, enrichment, and tactic navigation."""

from typing import List, Optional, Dict, Any
from app.domain.schemas.mitre import (
    MitreTechniqueRead,
    MitreTacticRead,
    MitreEnrichmentRead,
)
from app.mitre.taxonomy import (
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    RULE_TO_TECHNIQUE_MAP,
)


class MitreService:
    """Service providing MITRE ATT&CK Cloud matrix lookups, mappings, and enrichment."""

    def __init__(self):
        self._tactics = MITRE_TACTICS
        self._techniques = MITRE_TECHNIQUES
        self._rule_map = RULE_TO_TECHNIQUE_MAP

    def get_technique(self, technique_id: str) -> MitreTechniqueRead:
        """Looks up a technique by ID with safe fallback for unknown IDs."""
        clean_id = (technique_id or "").strip().upper()
        if clean_id in self._techniques:
            data = self._techniques[clean_id]
            return MitreTechniqueRead(
                id=data["id"],
                name=data["name"],
                tactic=data["tactic"],
                tactics=data.get("tactics", [data["tactic"]]),
                description=data["description"],
                data_sources=data.get("data_sources", []),
                detection_rules=data.get("detection_rules", []),
                is_known=True,
            )

        # Graceful fallback for uncataloged technique
        return MitreTechniqueRead(
            id=clean_id or "UNKNOWN",
            name=f"Custom Technique ({clean_id or 'UNKNOWN'})",
            tactic="Unknown",
            tactics=["Unknown"],
            description="Uncataloged or custom adversary technique identifier.",
            data_sources=[],
            detection_rules=[],
            is_known=False,
        )

    def get_technique_by_rule_id(self, rule_id: str) -> Optional[MitreTechniqueRead]:
        """Resolves mapped MITRE technique for a platform detection rule."""
        clean_rule_id = (rule_id or "").strip().upper()
        tech_id = self._rule_map.get(clean_rule_id)
        if tech_id:
            return self.get_technique(tech_id)
        return None

    def get_techniques_by_tactic(self, tactic_identifier: str) -> List[MitreTechniqueRead]:
        """Retrieves all techniques associated with a tactic (by ID e.g. TA0001 or Name)."""
        clean_target = (tactic_identifier or "").strip().lower()

        # If tactic ID provided, get standard name
        tactic_name = clean_target
        for tid, tdata in self._tactics.items():
            if tid.lower() == clean_target:
                tactic_name = tdata["name"].lower()
                break

        results: List[MitreTechniqueRead] = []
        for tech_id, tdata in self._techniques.items():
            primary_match = tdata.get("tactic", "").lower() == tactic_name
            secondary_match = any(
                t.lower() == tactic_name for t in tdata.get("tactics", [])
            )
            if primary_match or secondary_match:
                results.append(self.get_technique(tech_id))

        return results

    def list_tactics(self) -> List[MitreTacticRead]:
        """Returns all MITRE tactics populated with their cataloged techniques."""
        tactic_list: List[MitreTacticRead] = []
        for tactic_id, tdata in self._tactics.items():
            techniques = self.get_techniques_by_tactic(tdata["name"])
            tactic_list.append(
                MitreTacticRead(
                    id=tdata["id"],
                    name=tdata["name"],
                    description=tdata["description"],
                    techniques=techniques,
                )
            )
        return tactic_list

    def list_techniques(self) -> List[MitreTechniqueRead]:
        """Returns all registered MITRE techniques."""
        return [self.get_technique(tid) for tid in sorted(self._techniques.keys())]

    def enrich(
        self,
        technique_id: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> MitreEnrichmentRead:
        """Enriches an alert or detection with full MITRE context and metadata."""
        target_id = technique_id
        if not target_id and rule_id:
            target_id = self._rule_map.get(rule_id.strip().upper())

        resolved = self.get_technique(target_id or "UNKNOWN")
        severity_hint = None
        if resolved.is_known and resolved.id in self._techniques:
            severity_hint = self._techniques[resolved.id].get("severity_hint")

        # Merge detection rules
        rules = list(resolved.detection_rules)
        if rule_id and rule_id not in rules:
            rules.append(rule_id)

        return MitreEnrichmentRead(
            technique_id=resolved.id,
            technique_name=resolved.name,
            tactic=resolved.tactic,
            tactics=resolved.tactics,
            data_sources=resolved.data_sources,
            severity_hint=severity_hint,
            detection_rules=rules,
            is_known=resolved.is_known,
        )


# Global singleton instance
mitre_service = MitreService()

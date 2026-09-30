"""Initial core database schema

Revision ID: 0001_initial_core_schema
Revises: 
Create Date: 2026-09-25 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_core_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("hashed_password", sa.String(length=256), nullable=False),
        sa.Column("full_name", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="L1_ANALYST"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )

    # 2. raw_logs
    op.create_table(
        "raw_logs",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_system", sa.String(length=64), nullable=False),
        sa.Column(
            "raw_payload",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # 3. normalized_events
    # Note on Partitioning: In this initial migration, normalized_events is created as a single table
    # with timestamp indices. Monthly range partitioning can be enabled on PostgreSQL via table inheritance
    # or declarative partitioning once ingestion volume exceeds 1M+ rows per day.
    op.create_table(
        "normalized_events",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("raw_log_id", sa.CHAR(36), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_category", sa.String(length=64), nullable=False),
        sa.Column("event_name", sa.String(length=128), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=True),
        sa.Column("principal_name", sa.String(length=256), nullable=True),
        sa.Column("caller_ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("target_resource_id", sa.Text(), nullable=True),
        sa.Column("target_resource_name", sa.String(length=256), nullable=True),
        sa.Column("action_status", sa.String(length=32), nullable=False),
        sa.Column("geo_country", sa.String(length=64), nullable=True),
        sa.Column("geo_city", sa.String(length=128), nullable=True),
        sa.Column(
            "security_context",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["raw_log_id"], ["raw_logs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_norm_events_ts", "normalized_events", ["event_timestamp"], unique=False)
    op.create_index("idx_norm_events_principal", "normalized_events", ["principal_name", "event_timestamp"], unique=False)
    op.create_index("idx_norm_events_ip", "normalized_events", ["caller_ip", "event_timestamp"], unique=False)

    # 4. detection_rules
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("mitre_tactic", sa.String(length=64), nullable=False),
        sa.Column("mitre_technique_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "rule_logic",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id"),
    )

    # 5. incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("incident_number", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="NEW"),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "mitre_tactics",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "mitre_techniques",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("assigned_to", sa.CHAR(36), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_number"),
    )
    op.create_index("idx_incidents_status", "incidents", ["status"], unique=False)
    op.create_index("idx_incidents_severity", "incidents", ["severity"], unique=False)
    op.create_index("idx_incidents_risk", "incidents", ["risk_score"], unique=False)

    # 6. threat_detections
    op.create_table(
        "threat_detections",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("rule_id", sa.CHAR(36), nullable=False),
        sa.Column("event_id", sa.CHAR(36), nullable=False),
        sa.Column("incident_id", sa.CHAR(36), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("alert_summary", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["normalized_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_threat_detections_time", "threat_detections", ["detected_at"], unique=False)
    op.create_index("idx_threat_detections_severity", "threat_detections", ["severity"], unique=False)

    # 7. ml_anomaly_scores
    op.create_table(
        "ml_anomaly_scores",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("event_id", sa.CHAR(36), nullable=False),
        sa.Column("incident_id", sa.CHAR(36), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "feature_contributions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("is_anomalous", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["normalized_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ml_scores_event", "ml_anomaly_scores", ["event_id"], unique=False)
    op.create_index("idx_ml_scores_anomalous", "ml_anomaly_scores", ["is_anomalous"], unique=False)

    # 8. incident_timeline_events
    op.create_table(
        "incident_timeline_events",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("incident_id", sa.CHAR(36), nullable=False),
        sa.Column("event_id", sa.CHAR(36), nullable=False),
        sa.Column("correlation_reason", sa.String(length=256), nullable=False),
        sa.Column("sequence_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["normalized_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_timeline_order", "incident_timeline_events", ["incident_id", "sequence_order"], unique=False)

    # 9. playbooks
    op.create_table(
        "playbooks",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("trigger_severity", sa.String(length=32), nullable=False),
        sa.Column(
            "target_tactics",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "actions_schema",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("requires_human_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # 10. playbook_executions
    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("playbook_id", sa.CHAR(36), nullable=False),
        sa.Column("incident_id", sa.CHAR(36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("is_dry_run", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "execution_trace",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("executed_by", sa.CHAR(36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_playbook_exec_incident", "playbook_executions", ["incident_id"], unique=False)

    # 11. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.CHAR(36), nullable=False),
        sa.Column("user_id", sa.CHAR(36), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column(
            "metadata_payload",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("idx_audit_logs_time", "audit_logs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_audit_logs_time", table_name="audit_logs")
    op.drop_index("idx_audit_logs_action", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("idx_playbook_exec_incident", table_name="playbook_executions")
    op.drop_table("playbook_executions")

    op.drop_table("playbooks")

    op.drop_index("idx_timeline_order", table_name="incident_timeline_events")
    op.drop_table("incident_timeline_events")

    op.drop_index("idx_ml_scores_anomalous", table_name="ml_anomaly_scores")
    op.drop_index("idx_ml_scores_event", table_name="ml_anomaly_scores")
    op.drop_table("ml_anomaly_scores")

    op.drop_index("idx_threat_detections_severity", table_name="threat_detections")
    op.drop_index("idx_threat_detections_time", table_name="threat_detections")
    op.drop_table("threat_detections")

    op.drop_index("idx_incidents_risk", table_name="incidents")
    op.drop_index("idx_incidents_severity", table_name="incidents")
    op.drop_index("idx_incidents_status", table_name="incidents")
    op.drop_table("incidents")

    op.drop_table("detection_rules")

    op.drop_index("idx_norm_events_ip", table_name="normalized_events")
    op.drop_index("idx_norm_events_principal", table_name="normalized_events")
    op.drop_index("idx_norm_events_ts", table_name="normalized_events")
    op.drop_table("normalized_events")

    op.drop_table("raw_logs")

    op.drop_table("users")

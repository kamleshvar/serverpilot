"""Server onboarding, discovery, enrollment and monitoring.

Revision ID: b7c2d9f4a1e6
Revises: d9ea0ffa1ed4
Create Date: 2026-11-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b7c2d9f4a1e6"
down_revision = "d9ea0ffa1ed4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("servers", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("ip_address", sa.String(length=45), nullable=True)
        )
        batch_op.add_column(
            sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22")
        )
        batch_op.add_column(
            sa.Column(
                "ssh_username",
                sa.String(length=32),
                nullable=False,
                server_default="ubuntu",
            )
        )
        batch_op.add_column(
            sa.Column(
                "approval_status",
                sa.Enum(
                    "pending",
                    "approved",
                    "rejected",
                    name="serverapprovalstatus",
                    native_enum=False,
                    create_constraint=True,
                    length=48,
                ),
                nullable=False,
                server_default="pending",
            )
        )
        batch_op.add_column(
            sa.Column(
                "connection_status",
                sa.Enum(
                    "unknown",
                    "connected",
                    "failed",
                    "offline",
                    name="serverconnectionstatus",
                    native_enum=False,
                    create_constraint=True,
                    length=48,
                ),
                nullable=False,
                server_default="unknown",
            )
        )
        batch_op.add_column(
            sa.Column(
                "scan_status",
                sa.Enum(
                    "pending",
                    "running",
                    "succeeded",
                    "failed",
                    name="scanstatus",
                    native_enum=False,
                    create_constraint=True,
                    length=48,
                ),
                nullable=False,
                server_default="pending",
            )
        )
        batch_op.add_column(
            sa.Column(
                "agent_install_status",
                sa.Enum(
                    "not_installed",
                    "installing",
                    "installed",
                    "failed",
                    name="agentinstallstatus",
                    native_enum=False,
                    create_constraint=True,
                    length=48,
                ),
                nullable=False,
                server_default="not_installed",
            )
        )
        batch_op.add_column(
            sa.Column("operating_system", sa.String(length=120), nullable=True)
        )
        batch_op.add_column(
            sa.Column("os_version", sa.String(length=120), nullable=True)
        )
        batch_op.add_column(
            sa.Column("kernel_version", sa.String(length=120), nullable=True)
        )
        batch_op.add_column(
            sa.Column("cpu_model", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "docker_status",
                sa.String(length=32),
                nullable=False,
                server_default="unknown",
            )
        )
        batch_op.add_column(
            sa.Column("nginx_version", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "nginx_status",
                sa.String(length=32),
                nullable=False,
                server_default="unknown",
            )
        )
        batch_op.add_column(
            sa.Column("host_key_fingerprint", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("last_scan_error", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "last_ssh_connected_at", sa.DateTime(timezone=True), nullable=True
            )
        )
        batch_op.add_column(
            sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("deleted_by_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_foreign_key(
            op.f("fk_servers_deleted_by_id_users"),
            "users",
            ["deleted_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            op.f("ix_servers_ip_address"), ["ip_address"], unique=False
        )
        batch_op.create_index(
            op.f("ix_servers_approval_status"), ["approval_status"], unique=False
        )
        batch_op.create_index(
            op.f("ix_servers_deleted_at"), ["deleted_at"], unique=False
        )

    op.execute(
        "UPDATE servers SET approval_status = 'approved', "
        "connection_status = CASE WHEN last_heartbeat_at IS NOT NULL THEN 'connected' "
        "ELSE 'unknown' END"
    )

    op.create_table(
        "server_scans",
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("scanned_by_id", sa.String(length=36), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "succeeded",
                "failed",
                name="scanstatus",
                native_enum=False,
                create_constraint=True,
                length=48,
            ),
            nullable=False,
        ),
        sa.Column("scan_results", sa.JSON(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scanned_by_id"],
            ["users.id"],
            name=op.f("fk_server_scans_scanned_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("fk_server_scans_server_id_servers"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_server_scans")),
    )
    with op.batch_alter_table("server_scans", schema=None) as batch_op:
        batch_op.create_index(
            op.f("ix_server_scans_server_id"), ["server_id"], unique=False
        )
        batch_op.create_index(
            "ix_server_scans_server_time", ["server_id", "scanned_at"], unique=False
        )

    op.create_table(
        "server_resource_history",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("cpu_usage", sa.Float(), nullable=False),
        sa.Column("ram_usage", sa.Float(), nullable=False),
        sa.Column("storage_usage", sa.Float(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("fk_server_resource_history_server_id_servers"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_server_resource_history")),
    )
    with op.batch_alter_table("server_resource_history", schema=None) as batch_op:
        batch_op.create_index(
            op.f("ix_server_resource_history_server_id"), ["server_id"], unique=False
        )
        batch_op.create_index(
            "ix_server_resource_history_server_time",
            ["server_id", "recorded_at"],
            unique=False,
        )

    op.create_table(
        "agent_enrollments",
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_id", sa.String(length=36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_agent_uid", sa.String(length=64), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_agent_enrollments_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["server_id"],
            ["servers.id"],
            name=op.f("fk_agent_enrollments_server_id_servers"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_enrollments")),
        sa.UniqueConstraint("token_hash", name="uq_agent_enrollments_token_hash"),
    )
    with op.batch_alter_table("agent_enrollments", schema=None) as batch_op:
        batch_op.create_index(
            op.f("ix_agent_enrollments_server_id"), ["server_id"], unique=False
        )
        batch_op.create_index(
            "ix_agent_enrollments_expires", ["expires_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("agent_enrollments", schema=None) as batch_op:
        batch_op.drop_index("ix_agent_enrollments_expires")
        batch_op.drop_index(op.f("ix_agent_enrollments_server_id"))
    op.drop_table("agent_enrollments")

    with op.batch_alter_table("server_resource_history", schema=None) as batch_op:
        batch_op.drop_index("ix_server_resource_history_server_time")
        batch_op.drop_index(op.f("ix_server_resource_history_server_id"))
    op.drop_table("server_resource_history")

    with op.batch_alter_table("server_scans", schema=None) as batch_op:
        batch_op.drop_index("ix_server_scans_server_time")
        batch_op.drop_index(op.f("ix_server_scans_server_id"))
    op.drop_table("server_scans")

    with op.batch_alter_table("servers", schema=None) as batch_op:
        batch_op.drop_index(op.f("ix_servers_deleted_at"))
        batch_op.drop_index(op.f("ix_servers_approval_status"))
        batch_op.drop_index(op.f("ix_servers_ip_address"))
        batch_op.drop_constraint(
            op.f("fk_servers_deleted_by_id_users"), type_="foreignkey"
        )
        batch_op.drop_column("deleted_by_id")
        batch_op.drop_column("deleted_at")
        batch_op.drop_column("last_ssh_connected_at")
        batch_op.drop_column("last_scan_error")
        batch_op.drop_column("last_scan_at")
        batch_op.drop_column("host_key_fingerprint")
        batch_op.drop_column("nginx_status")
        batch_op.drop_column("nginx_version")
        batch_op.drop_column("docker_status")
        batch_op.drop_column("cpu_model")
        batch_op.drop_column("kernel_version")
        batch_op.drop_column("os_version")
        batch_op.drop_column("operating_system")
        batch_op.drop_column("agent_install_status")
        batch_op.drop_column("scan_status")
        batch_op.drop_column("connection_status")
        batch_op.drop_column("approval_status")
        batch_op.drop_column("ssh_username")
        batch_op.drop_column("ssh_port")
        batch_op.drop_column("ip_address")

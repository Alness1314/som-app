"""Add per-device opt-in for untrusted HTTPS certificates."""
from alembic import op
from sqlalchemy import Boolean, Column, inspect

revision = "0002_device_tls_policy"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("devices")}
    if "allow_untrusted_tls" not in columns:
        op.add_column("devices", Column("allow_untrusted_tls", Boolean(), nullable=False, server_default="0"))


def downgrade():
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("devices")}
    if "allow_untrusted_tls" in columns:
        op.drop_column("devices", "allow_untrusted_tls")

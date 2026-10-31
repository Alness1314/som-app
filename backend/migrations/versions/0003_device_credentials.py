"""Store per-device credentials as Windows DPAPI ciphertext."""
from alembic import op
import sqlalchemy as sa

revision = "0003_device_credentials"
down_revision = "0002_device_tls_policy"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "device_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("username_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("password_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_credentials_device_id", "device_credentials", ["device_id"], unique=True)


def downgrade():
    op.drop_index("ix_device_credentials_device_id", table_name="device_credentials")
    op.drop_table("device_credentials")

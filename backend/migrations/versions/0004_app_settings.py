"""Add local application settings storage."""
from alembic import op
import sqlalchemy as sa

revision = "0004_app_settings"
down_revision = "0003_device_credentials"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=120), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

def downgrade():
    op.drop_table("app_settings")

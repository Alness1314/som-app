"""Initial schema."""
from alembic import op
from sqlalchemy import inspect
from som_api.db import Base, engine
from som_api import models
revision='0001_initial';down_revision=None;branch_labels=None;depends_on=None
def upgrade():Base.metadata.create_all(bind=engine)
def downgrade():
    inspector=inspect(engine)
    for table in reversed(Base.metadata.sorted_tables):
        if inspector.has_table(table.name):op.drop_table(table.name)

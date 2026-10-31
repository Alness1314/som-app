import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(os.environ.get("SOM_DATA_DIR", Path.home() / "AppData" / "Roaming" / "SOM" / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = Path(os.environ.get("SOM_BACKUP_DIR", DATA_DIR / "backups"))
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
AUTOMATION_STAGING_DIR = DATA_DIR / "automation-staging"
AUTOMATION_STAGING_DIR.mkdir(parents=True, exist_ok=True)
engine = create_engine(f"sqlite:///{DATA_DIR / 'som.db'}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

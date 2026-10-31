import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from som_api.db import Base
from som_api.models import Device, DeviceCredential
from som_api.services.credential_vault import protect_secret, unprotect_secret

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI solo está disponible en Windows")


def test_dpapi_round_trip_keeps_plaintext_out_of_ciphertext():
    sample = "som synthetic vault check"
    ciphertext = protect_secret(sample)
    assert sample.encode("utf-8") not in ciphertext
    assert unprotect_secret(ciphertext) == sample


def test_sqlite_stores_only_dpapi_ciphertext(tmp_path):
    database = tmp_path / "credential-test.sqlite"
    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    username = "synthetic-user"
    password = "synthetic-password-not-real"
    with Session(engine) as db:
        device = Device(name="Synthetic device", kind="FIREWALL", url="https://127.0.0.1/")
        db.add(device)
        db.flush()
        row = DeviceCredential(
            device_id=device.id,
            username_encrypted=protect_secret(username),
            password_encrypted=protect_secret(password),
        )
        db.add(row)
        db.commit()
        stored = db.query(DeviceCredential).filter_by(device_id=device.id).one()
        assert username.encode("utf-8") not in stored.username_encrypted
        assert password.encode("utf-8") not in stored.password_encrypted
        assert unprotect_secret(stored.username_encrypted) == username
        assert unprotect_secret(stored.password_encrypted) == password
    engine.dispose()

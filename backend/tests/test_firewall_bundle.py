import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import base64
import zipfile
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from som_api import main
from som_api.db import Base, get_db
from som_api.models import Device


def test_firewall_bundle_is_verified_and_registered(tmp_path, monkeypatch):
    db_file=tmp_path/'test.sqlite'
    test_engine=create_engine(f"sqlite:///{db_file}",connect_args={"check_same_thread":False})
    Base.metadata.create_all(test_engine)
    TestSession=sessionmaker(bind=test_engine,autoflush=False,expire_on_commit=False)
    monkeypatch.setattr(main,"SessionLocal",TestSession)
    monkeypatch.setattr(main,"AUTOMATION_STAGING_DIR",tmp_path/'staging')
    monkeypatch.setattr(main,"BACKUP_DIR",tmp_path/'fallback-backups')
    monkeypatch.setattr(main,"TOKEN","synthetic-test-token")

    def override_get_db():
        session=TestSession()
        try: yield session
        finally: session.close()

    main.app.dependency_overrides[get_db]=override_get_db
    stage=tmp_path/'staging'/'synthetic-run'
    stage.mkdir(parents=True)
    categories=("EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","THREATLOG","SESSIONLOG","NATLOG","URLLOG")
    items=[]
    for category in categories:
        for fmt in ("TXT","CSV"):
            file=stage/f"FW_{category}_25_10_2026_{fmt}.zip"
            with zipfile.ZipFile(file,"w") as archive:
                archive.writestr(f"synthetic-{fmt.lower()}.{fmt.lower()}","synthetic test data only")
            items.append({"path":str(file),"category":category,"format":fmt})

    try:
        with TestClient(main.app) as client:
            device=next(row for row in client.get("/api/devices",headers={"X-SOM-Token":"synthetic-test-token"}).json() if row["kind"]=="FIREWALL")
            response=client.post("/api/backups/internal/firewall-bundle",headers={"X-SOM-Token":"synthetic-test-token"},json={"device_id":device["id"],"report_date":"25_10_2026","files":items})
            assert response.status_code==200,response.text
            result=response.json()
            assert result["file_count"]==14
            stored=Path(result["path"])
            assert stored.name=="FW_LOGS_25_10_2026.zip"
            with zipfile.ZipFile(stored) as archive:
                assert len([name for name in archive.namelist() if name!="MANIFEST.json"])==14
                assert "MANIFEST.json" in archive.namelist()
            assert client.get("/api/backups",headers={"X-SOM-Token":"synthetic-test-token"}).json()[0]["filename"]==stored.name
    finally:
        main.app.dependency_overrides.pop(get_db,None)
        test_engine.dispose()


def test_waf_bundle_accepts_and_displays_empty_log_capture(tmp_path, monkeypatch):
    test_engine=create_engine(f"sqlite:///{tmp_path/'waf-test.sqlite'}",connect_args={"check_same_thread":False})
    Base.metadata.create_all(test_engine)
    TestSession=sessionmaker(bind=test_engine,autoflush=False,expire_on_commit=False)
    monkeypatch.setattr(main,"SessionLocal",TestSession)
    monkeypatch.setattr(main,"AUTOMATION_STAGING_DIR",tmp_path/'staging')
    monkeypatch.setattr(main,"BACKUP_DIR",tmp_path/'fallback-backups')
    monkeypatch.setattr(main,"TOKEN","synthetic-test-token")

    def override_get_db():
        session=TestSession()
        try: yield session
        finally: session.close()

    main.app.dependency_overrides[get_db]=override_get_db
    stage=tmp_path/'staging'/'synthetic-waf-run'
    stage.mkdir(parents=True)
    categories=("EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","NATLOG","WEBACCESSLOG","NETWORKSECURITYLOG","WEBSECURITYLOG")
    empty_capture=stage/'WAF_CONFIGURATIONLOG_25_10_2026_SIN_LOGS.png'
    empty_capture.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p3sAAAAASUVORK5CYII="))
    items=[{"path":str(empty_capture),"category":"CONFIGURATIONLOG","format":"PNG"}]
    for category in categories:
        if category=="CONFIGURATIONLOG": continue
        for fmt in ("TXT","CSV"):
            file=stage/f"WAF_{category}_25_10_2026_{fmt}.zip"
            with zipfile.ZipFile(file,"w") as archive: archive.writestr(f"synthetic.{fmt.lower()}","synthetic test data only")
            items.append({"path":str(file),"category":category,"format":fmt})

    try:
        with TestClient(main.app) as client:
            headers={"X-SOM-Token":"synthetic-test-token"}
            device=next(row for row in client.get("/api/devices",headers=headers).json() if row["kind"]=="WAF")
            response=client.post("/api/backups/internal/firewall-bundle",headers=headers,json={"device_id":device["id"],"report_date":"25_10_2026","files":items})
            assert response.status_code==200,response.text
            result=response.json()
            assert result["backup"]["filename"]=="WAF_LOGS_25_10_2026.zip"
            stored=Path(result["path"])
            with zipfile.ZipFile(stored) as archive: assert "WAF_CONFIGURATIONLOG_25_10_2026_SIN_LOGS.png" in archive.namelist()
            listing=client.get(f"/api/backups/{result['backup']['id']}/contents",headers=headers).json()["entries"]
            capture=next(entry for entry in listing if entry["name"].endswith("SIN_LOGS.png"))
            assert capture["viewable"] and capture["is_image"]
            image=client.get(f"/api/backups/{result['backup']['id']}/entries/{capture['index']}",headers=headers).json()
            assert image["media_type"]=="image/png" and image["image_data"]
    finally:
        main.app.dependency_overrides.pop(get_db,None)
        test_engine.dispose()

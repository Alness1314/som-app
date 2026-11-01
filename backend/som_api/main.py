import asyncio
import base64
import csv
import gzip
import hashlib
import json
import io
import os
import secrets
import shutil
import tarfile
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session
from .db import AUTOMATION_STAGING_DIR, Base, BACKUP_DIR, SessionLocal, engine, get_db
from .models import Activity, AppSetting, AuditLog, Backup, ConnectivityCheck, Device, DeviceCredential
from .schemas import ActivityIn, BackupBundleIn, BackupDeleteIn, DeviceCredentialsIn, DeviceIn, StorageSettingIn, BackupScheduleIn, BackupScheduleClaimIn, BackupScheduleFinishIn
from .services.files import MAX_FILE, MAX_UNZIPPED, inspect_file, manifest
from .services.credential_vault import protect_secret, unprotect_secret
from .services.log_analysis import analyze_firewall_zip, _decode, _parse_txt

Base.metadata.create_all(bind=engine)
# Additive migration for existing local SQLite databases.
with engine.begin() as connection:
    device_columns = {column["name"] for column in inspect(connection).get_columns("devices")}
    if "allow_untrusted_tls" not in device_columns:
        connection.execute(text("ALTER TABLE devices ADD COLUMN allow_untrusted_tls BOOLEAN NOT NULL DEFAULT 0"))
app = FastAPI(title="SOM Local API", docs_url=None, redoc_url=None)
TOKEN = os.environ.get("SOM_TOKEN", "")

@app.middleware("http")
async def local_auth(request: Request, call_next):
    if request.url.path == "/api/health":
        if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}: return JSONResponse({"detail":"local only"}, status_code=403)
    elif request.headers.get("x-som-token") != TOKEN or not TOKEN:
        return JSONResponse({"detail":"Unauthorized"}, status_code=401)
    if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        return JSONResponse({"detail":"Localhost only"}, status_code=403)
    return await call_next(request)

@app.get("/api/health")
def health(): return {"status":"ok"}

def configured_backup_dir(db: Session) -> Path:
    setting = db.get(AppSetting, "backup_storage_path")
    return Path(setting.value) if setting else BACKUP_DIR

@app.get("/api/settings/storage")
def get_storage_setting(db: Session=Depends(get_db)):
    kind = db.get(AppSetting, "backup_storage_type")
    path = configured_backup_dir(db)
    return {"destination_type":kind.value if kind else "local", "path":str(path), "configured":kind is not None}

@app.put("/api/settings/storage")
def put_storage_setting(body:StorageSettingIn,db:Session=Depends(get_db)):
    raw_path=body.path.strip()
    if not raw_path: raise HTTPException(422,"Selecciona una carpeta de destino")
    try:
        target=Path(raw_path).expanduser()
        if not target.is_absolute(): raise ValueError("La ruta debe ser absoluta")
        target.mkdir(parents=True,exist_ok=True)
        probe=target/f".som-write-check-{secrets.token_hex(8)}"
        probe.write_bytes(b"som")
        probe.unlink()
    except (OSError,ValueError) as exc:
        raise HTTPException(400,"La carpeta no está disponible o no permite escritura") from exc
    for key,value in (("backup_storage_path",str(target.resolve())),("backup_storage_type",body.destination_type)):
        row=db.get(AppSetting,key)
        if row is None: db.add(AppSetting(key=key,value=value))
        else: row.value=value
    db.commit();audit(db,"settings.backup_storage",body.destination_type)
    return {"destination_type":body.destination_type,"path":str(target.resolve()),"configured":True}

@app.get("/api/settings/backup-schedule")
def get_backup_schedule(db:Session=Depends(get_db)):
    # Migrate the previous single-job schedule exactly once. Keep the legacy
    # activation/time for all three job kinds, but resolve each device by kind.
    legacy_enabled=db.get(AppSetting,"backup_schedule_enabled")
    legacy_time=db.get(AppSetting,"backup_schedule_time")
    migration=db.get(AppSetting,"backup_schedule_jobs_version")
    migrating=migration is None and any((legacy_enabled,legacy_time,db.get(AppSetting,"backup_schedule_device_id")))
    fallback_enabled=legacy_enabled.value=="true" if legacy_enabled else False
    fallback_time=legacy_time.value if legacy_time and len(legacy_time.value)==5 else "23:00"
    jobs=[]
    for kind in ("FIREWALL","WAF","BDS"):
        suffix=kind.lower()
        row_enabled=db.get(AppSetting,f"backup_schedule_{suffix}_enabled")
        row_time=db.get(AppSetting,f"backup_schedule_{suffix}_time")
        row_device=db.get(AppSetting,f"backup_schedule_{suffix}_device_id")
        row_last=db.get(AppSetting,f"backup_schedule_{suffix}_last_run_date")
        row_attempt=db.get(AppSetting,f"backup_schedule_{suffix}_last_attempt_date")
        # A legacy/partial run may have written the date without actually
        # completing and persisting the bundle. Only a success audit proves
        # this task completed for that day.
        if row_last and not db.query(AuditLog.id).filter(
            AuditLog.action=="backup.schedule.success",
            AuditLog.detail.startswith(f"{kind} date={row_last.value}:"),
        ).first():
            db.delete(row_last)
            row_last=None
        device=(db.get(Device,int(row_device.value)) if row_device and row_device.value.isdigit() else None)
        if not device or device.kind!=kind or not device.enabled:
            device=db.query(Device).filter(Device.kind==kind,Device.enabled.is_(True)).order_by(Device.id).first()
        # Persist migration so the scheduler can atomically claim each job.
        defaults={f"backup_schedule_{suffix}_enabled":"true" if fallback_enabled else "false",
            f"backup_schedule_{suffix}_time":fallback_time,
            f"backup_schedule_{suffix}_device_id":str(device.id) if device else ""}
        for key,value in defaults.items():
            row=db.get(AppSetting,key)
            if migrating or row is None:
                if row is None: db.add(AppSetting(key=key,value=value))
                else: row.value=value
        saved_enabled=db.get(AppSetting,f"backup_schedule_{suffix}_enabled")
        saved_time=db.get(AppSetting,f"backup_schedule_{suffix}_time")
        jobs.append({"kind":kind,"enabled":saved_enabled.value=="true" if saved_enabled else fallback_enabled,
            "time":saved_time.value if saved_time else fallback_time,"device_id":device.id if device else None,
            "device_name":device.name if device else None,"last_run_date":row_last.value if row_last else None,
            "last_attempt_date":row_attempt.value if row_attempt else None})
    if migration is None:
        db.add(AppSetting(key="backup_schedule_jobs_version",value="1"))
    db.commit()
    return {"jobs":jobs,"timezone":"local"}

@app.put("/api/settings/backup-schedule")
def put_backup_schedule(body:BackupScheduleIn,db:Session=Depends(get_db)):
    if {job.kind for job in body.jobs}!={"FIREWALL","WAF","BDS"}: raise HTTPException(422,"Configura exactamente un job para Firewall, WAF y BDS")
    for job in body.jobs:
        device=db.get(Device,job.device_id)
        if not device or device.kind!=job.kind or not device.enabled: raise HTTPException(422,f"Selecciona un dispositivo {job.kind} habilitado")
        suffix=job.kind.lower()
        values={f"backup_schedule_{suffix}_enabled":"true" if job.enabled else "false",f"backup_schedule_{suffix}_time":job.time,f"backup_schedule_{suffix}_device_id":str(job.device_id)}
        for key,value in values.items():
            row=db.get(AppSetting,key)
            if row is None: db.add(AppSetting(key=key,value=value))
            else: row.value=value
    version=db.get(AppSetting,"backup_schedule_jobs_version")
    if version is None: db.add(AppSetting(key="backup_schedule_jobs_version",value="1"))
    else: version.value="1"
    db.commit()
    audit(db,"settings.backup_schedule", "; ".join(f"{job.kind}={'enabled' if job.enabled else 'disabled'} {job.time} device={job.device_id}" for job in body.jobs))
    return get_backup_schedule(db)

@app.post("/api/settings/backup-schedule/claim")
def claim_backup_schedule(body:BackupScheduleClaimIn,db:Session=Depends(get_db)):
    suffix=body.kind.lower()
    enabled=db.get(AppSetting,f"backup_schedule_{suffix}_enabled")
    last=db.get(AppSetting,f"backup_schedule_{suffix}_last_run_date")
    if not enabled or enabled.value!="true": return {"claimed":False}
    if last and last.value==body.run_date:
        completed=db.query(AuditLog.id).filter(
            AuditLog.action=="backup.schedule.success",
            AuditLog.detail.startswith(f"{body.kind} date={body.run_date}:"),
        ).first()
        if completed: return {"claimed":False,"reason":"already-completed"}
        # Old builds could stamp last_run_date before creating a saved bundle.
        db.delete(last)
    claim_date=db.get(AppSetting,f"backup_schedule_{suffix}_claimed_date")
    claim_time=db.get(AppSetting,f"backup_schedule_{suffix}_claimed_at")
    if claim_date and claim_date.value==body.run_date and claim_time:
        try:
            claimed_at=datetime.fromisoformat(claim_time.value)
            if (datetime.now(timezone.utc)-claimed_at.astimezone(timezone.utc)).total_seconds()<6*60*60:
                return {"claimed":False,"reason":"already-running"}
        except ValueError:
            pass
    retry=db.get(AppSetting,f"backup_schedule_{suffix}_retry_after")
    if retry:
        try:
            if datetime.now(timezone.utc)<datetime.fromisoformat(retry.value).astimezone(timezone.utc):
                return {"claimed":False,"reason":"retry-backoff"}
        except ValueError:
            pass
    now=datetime.now(timezone.utc)
    values={f"backup_schedule_{suffix}_claimed_date":body.run_date,
        f"backup_schedule_{suffix}_claimed_at":now.isoformat(),
        # Record the attempt at claim time. Successors can proceed after a
        # failed or interrupted job instead of waiting forever for a success.
        f"backup_schedule_{suffix}_last_attempt_date":body.run_date}
    for key,value in values.items():
        row=db.get(AppSetting,key)
        if row is None: db.add(AppSetting(key=key,value=value))
        else: row.value=value
    db.commit()
    return {"claimed":True}

@app.post("/api/settings/backup-schedule/finish")
def finish_backup_schedule(body:BackupScheduleFinishIn,db:Session=Depends(get_db)):
    suffix=body.kind.lower()
    claimed=db.get(AppSetting,f"backup_schedule_{suffix}_claimed_date")
    if not claimed or claimed.value!=body.run_date:
        raise HTTPException(409,"La ejecución programada ya no tiene una reserva activa")
    if body.success:
        key=f"backup_schedule_{suffix}_last_run_date"
        last=db.get(AppSetting,key)
        if last is None: db.add(AppSetting(key=key,value=body.run_date))
        else: last.value=body.run_date
        retry=db.get(AppSetting,f"backup_schedule_{suffix}_retry_after")
        if retry is not None: db.delete(retry)
        audit(db,"backup.schedule.success",f"{body.kind} date={body.run_date}: {(body.message or 'respaldo guardado')}")
    else:
        retry_at=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()
        key=f"backup_schedule_{suffix}_retry_after"
        retry=db.get(AppSetting,key)
        if retry is None: db.add(AppSetting(key=key,value=retry_at))
        else: retry.value=retry_at
        audit(db,"backup.schedule.failure",f"{body.kind} date={body.run_date}: {(body.message or 'falló el respaldo')}")
    attempt_key=f"backup_schedule_{suffix}_last_attempt_date"
    attempt=db.get(AppSetting,attempt_key)
    if attempt is None: db.add(AppSetting(key=attempt_key,value=body.run_date))
    else: attempt.value=body.run_date
    for key in (f"backup_schedule_{suffix}_claimed_date",f"backup_schedule_{suffix}_claimed_at"):
        row=db.get(AppSetting,key)
        if row is not None: db.delete(row)
    db.commit()
    return {"finished":True,"success":body.success}

def audit(db: Session, action: str, detail: str):
    db.add(AuditLog(action=action, detail=detail[:2000])); db.commit()

@app.on_event("startup")
def seed_devices():
    with SessionLocal() as db:
        if db.query(Device).count() == 0:
            db.add_all([Device(name="Hillstone Networks A2700",kind="FIREWALL",url="https://192.168.0.1:8443/#icenter"),Device(name="Hillstone Networks W620S",kind="WAF",url="https://10.10.10.2/"),Device(name="Hillstone Networks I1870",kind="BDS",url="https://192.168.0.175/#icenter")]); db.commit()

@app.get("/api/devices")
def devices(db: Session=Depends(get_db)):
    return [{"id":d.id,"name":d.name,"kind":d.kind,"url":d.url,"enabled":d.enabled,"allow_untrusted_tls":d.allow_untrusted_tls} for d in db.query(Device).order_by(Device.id)]

@app.post("/api/devices")
def add_device(body: DeviceIn, db: Session=Depends(get_db)):
    d=Device(**body.model_dump(mode="json")); db.add(d)
    try: db.commit(); db.refresh(d)
    except Exception as exc: db.rollback(); raise HTTPException(409,"No se pudo registrar el dispositivo") from exc
    audit(db,"device.create",d.name); return {"id":d.id,"name":d.name,"kind":d.kind,"url":d.url,"enabled":d.enabled,"allow_untrusted_tls":d.allow_untrusted_tls}

@app.put("/api/devices/{device_id}")
def update_device(device_id:int, body:DeviceIn, db:Session=Depends(get_db)):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,"Dispositivo no encontrado")
    for k,v in body.model_dump(mode="json").items(): setattr(d,k,v)
    db.commit(); audit(db,"device.update",d.name); return {"id":d.id,"name":d.name,"kind":d.kind,"url":d.url,"enabled":d.enabled,"allow_untrusted_tls":d.allow_untrusted_tls}

@app.delete("/api/devices/{device_id}",status_code=204)
def delete_device(device_id:int,db:Session=Depends(get_db)):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,"Dispositivo no encontrado")
    db.delete(d); db.commit(); audit(db,"device.delete",str(device_id)); return Response(status_code=204)

@app.get("/api/devices/{device_id}/credentials")
def credential_status(device_id:int,db:Session=Depends(get_db)):
    if not db.get(Device,device_id): raise HTTPException(404,"Dispositivo no encontrado")
    row=db.query(DeviceCredential).filter_by(device_id=device_id).first()
    return {"configured":row is not None,"updated_at":row.updated_at.isoformat() if row else None}

@app.put("/api/devices/{device_id}/credentials")
def save_device_credentials(device_id:int,body:DeviceCredentialsIn,db:Session=Depends(get_db)):
    device=db.get(Device,device_id)
    if not device: raise HTTPException(404,"Dispositivo no encontrado")
    if device.allow_untrusted_tls and not body.confirm_untrusted_tls:
        raise HTTPException(400,"Confirma que entiendes que el certificado TLS de este dispositivo no se valida antes de enviar credenciales")
    try:
        username_encrypted=protect_secret(body.username)
        password_encrypted=protect_secret(body.password)
    except (OSError,RuntimeError) as exc:
        raise HTTPException(503,"No se pudieron proteger las credenciales con Windows DPAPI") from exc
    row=db.query(DeviceCredential).filter_by(device_id=device_id).first()
    if row is None:
        row=DeviceCredential(device_id=device_id,username_encrypted=username_encrypted,password_encrypted=password_encrypted)
        db.add(row)
    else:
        row.username_encrypted=username_encrypted
        row.password_encrypted=password_encrypted
    db.commit(); db.refresh(row)
    audit(db,"device.credentials.save",device.name)
    return {"configured":True,"updated_at":row.updated_at.isoformat()}

@app.delete("/api/devices/{device_id}/credentials",status_code=204)
def delete_device_credentials(device_id:int,db:Session=Depends(get_db)):
    row=db.query(DeviceCredential).filter_by(device_id=device_id).first()
    if row is None:
        if not db.get(Device,device_id): raise HTTPException(404,"Dispositivo no encontrado")
        return Response(status_code=204)
    device_name=db.get(Device,device_id).name
    db.delete(row); db.commit(); audit(db,"device.credentials.delete",device_name)
    return Response(status_code=204)

@app.get("/api/devices/{device_id}/credentials/automation")
def credentials_for_local_automation(device_id:int,response:Response,db:Session=Depends(get_db)):
    """Internal Electron-only retrieval; this route is deliberately excluded from renderer IPC."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    row=db.query(DeviceCredential).filter_by(device_id=device_id).first()
    if row is None: raise HTTPException(404,"No hay credenciales guardadas para este dispositivo")
    try:
        return {"username":unprotect_secret(row.username_encrypted),"password":unprotect_secret(row.password_encrypted)}
    except (OSError,RuntimeError,UnicodeError) as exc:
        raise HTTPException(500,"No se pudieron descifrar las credenciales del dispositivo en este usuario de Windows") from exc

@app.post("/api/devices/{device_id}/check")
async def check_device(device_id:int,db:Session=Depends(get_db)):
    d=db.get(Device,device_id)
    if not d: raise HTTPException(404,"Dispositivo no encontrado")
    parsed=urlparse(d.url)
    if parsed.scheme!="https" or not parsed.hostname: raise HTTPException(400,"Se requiere URL HTTPS válida")
    start=time.perf_counter(); success=False; tls_valid=None; error=None
    try:
        async with httpx.AsyncClient(verify=not d.allow_untrusted_tls,timeout=8,follow_redirects=False) as client: response=await client.get(d.url.split('#')[0]); success=response.status_code<500
        tls_valid=None if d.allow_untrusted_tls else True
        if d.allow_untrusted_tls:
            error="Respuesta HTTPS recibida; certificado TLS no validado"
    except httpx.ConnectError as exc:
        error="Error TLS/certificado o conexión: "+str(exc)[:500]
        tls_valid=False if "SSL" in str(exc).upper() or "CERTIFICATE" in str(exc).upper() else None
    except httpx.TimeoutException: error="Tiempo de espera agotado"
    except Exception as exc: error=str(exc)[:500]
    latency=round((time.perf_counter()-start)*1000)
    row=ConnectivityCheck(device_id=device_id,success=success,latency_ms=latency,error=error,tls_valid=tls_valid);db.add(row);db.commit(); audit(db,"device.check",f"{d.name}: {'ok' if success else 'falló'}")
    return {"success":success,"latency_ms":latency,"error":error,"tls_valid":tls_valid,"vpn_status":"unknown"}

@app.get("/api/checks")
def checks(db:Session=Depends(get_db)):
    return [{"id":c.id,"device_id":c.device_id,"checked_at":c.checked_at.isoformat(),"success":c.success,"latency_ms":c.latency_ms,"error":c.error,"tls_valid":c.tls_valid} for c in db.query(ConnectivityCheck).order_by(ConnectivityCheck.checked_at.desc()).limit(100)]

@app.get("/api/backups")
def backups(db:Session=Depends(get_db)):
    return manifest(db.query(Backup).order_by(Backup.created_at.desc()).limit(500).all())

@app.delete("/api/backups/{backup_id}")
def delete_backup(backup_id:int, body:BackupDeleteIn, db:Session=Depends(get_db)):
    row=db.get(Backup,backup_id)
    if row is None: raise HTTPException(404,"Respaldo no encontrado")
    configured=configured_backup_dir(db).resolve()
    stored=Path(row.stored_path)
    try:
        if stored.is_symlink(): raise ValueError("El respaldo es un enlace simbólico")
        resolved=stored.resolve(strict=True)
        if not resolved.is_file() or not resolved.is_relative_to(configured): raise ValueError("El archivo no pertenece a la carpeta de respaldos configurada")
    except (OSError,ValueError) as exc:
        raise HTTPException(400,str(exc)) from exc
    # Keep a shared archive if another imported record references the same file.
    shared=db.query(Backup.id).filter(Backup.stored_path==row.stored_path,Backup.id!=row.id).first() is not None
    tombstone=None
    try:
        if not shared:
            tombstone=resolved.with_name(f".{resolved.name}.{secrets.token_hex(8)}.deleting")
            os.replace(resolved,tombstone)
        detail=f"device={row.device_id} filename={row.filename} sha256={row.sha256} motivo={body.reason}"
        db.delete(row)
        db.add(AuditLog(action="backup.delete",detail=detail[:2000]))
        db.commit()
        if tombstone is not None:
            try: tombstone.unlink(missing_ok=True)
            except OSError: pass
    except Exception as exc:
        db.rollback()
        if tombstone is not None and tombstone.exists():
            try: os.replace(tombstone,resolved)
            except OSError: pass
        raise HTTPException(500,"No se pudo eliminar y registrar el respaldo") from exc
    return {"deleted":True,"backup_id":backup_id}

def verified_backup_archive(backup_id:int,db:Session):
    row=db.get(Backup,backup_id)
    if not row: raise HTTPException(404,"Respaldo no encontrado")
    path=Path(row.stored_path)
    try:
        resolved=path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_file(): raise ValueError("El archivo registrado no está disponible")
        fmt,digest,_size=inspect_file(resolved)
        if fmt!="ZIP" or digest!=row.sha256: raise ValueError("El ZIP no coincide con el archivo validado al registrarlo")
        archive=zipfile.ZipFile(resolved)
        validate_archive(archive)
        return row,resolved,archive
    except (OSError,ValueError,zipfile.BadZipFile) as exc:
        raise HTTPException(400,str(exc)) from exc

def validate_archive(archive:zipfile.ZipFile):
    total=0
    for item in archive.infolist():
        member=Path(item.filename)
        if member.is_absolute() or ".." in member.parts or item.filename.startswith(("/","\\")): raise ValueError("El ZIP contiene una ruta insegura")
        if (item.external_attr>>16)&0o170000==0o120000: raise ValueError("El ZIP contiene un enlace simbólico")
        total+=item.file_size
        if total>MAX_UNZIPPED: raise ValueError("El ZIP excede el límite descomprimido")
        if item.file_size>MAX_FILE: raise ValueError("Un archivo dentro del ZIP excede el límite de 512 MiB")
        if item.file_size and item.compress_size==0: raise ValueError("ZIP inválido")
        if item.compress_size and item.file_size/item.compress_size>1000: raise ValueError("El ZIP excede la relación de compresión permitida")

def _txt_export_bytes(path:Path)->bytes:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            validate_archive(archive)
            candidates=[item for item in archive.infolist() if not item.is_dir() and Path(item.filename).suffix.lower()==".txt"]
            if len(candidates)!=1: raise ValueError("La exportación TXT debe contener exactamente un archivo .txt para convertir")
            return archive.read(candidates[0])
    if path.suffix.lower()!=".txt": raise ValueError("La exportación seleccionada como TXT no es un .txt ni un ZIP con un .txt interno")
    return path.read_bytes()

def _txt_export_to_csv(data:bytes,category:str)->bytes:
    parsed=_parse_txt(data,category)
    if not parsed: raise ValueError(f"No se pudo convertir el TXT de {category}: no contiene filas reconocibles")
    output=io.StringIO(newline="")
    writer=csv.writer(output,lineterminator="\r\n")
    table=category in {"EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","THREATLOG"}
    for timestamp,level,message in parsed:
        writer.writerow((timestamp,level,message) if table else (timestamp,message))
    return output.getvalue().encode("utf-8-sig")

def _is_log_text(data:bytes)->bool:
    if data.startswith((b"\xff\xfe",b"\xfe\xff")):
        return True
    sample=data[:8192]
    if not sample or b"\x00" in sample:
        return False
    printable=sum(byte in (9,10,13) or 32<=byte<=126 or byte>=128 for byte in sample)
    return printable/len(sample)>=0.82

def _unpack_log_bytes(data:bytes,limit:int=MAX_FILE,depth:int=0)->bytes:
    """Unwrap gzip or tar.gz payloads and reject binary data masquerading as a log."""
    if depth>4:
        raise ValueError("El log contiene demasiadas capas de compresión")
    if data.startswith(b"\x1f\x8b"):
        try:
            with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as packed:
                candidates=[]
                for member in packed.getmembers():
                    if not member.isfile():
                        continue
                    name=member.name.replace("\\","/")
                    parts=Path(name).parts
                    if not name or name.startswith("/") or ".." in parts or Path(name).is_absolute() or (parts and parts[0].endswith(":")):
                        raise ValueError("El TAR.GZ contiene una ruta insegura")
                    if Path(name).suffix.lower() not in {".txt",".log",".csv",".gz",".tgz"}:
                        continue
                    if member.size<0 or member.size>limit:
                        raise ValueError("El log descomprimido excede el límite permitido")
                    candidates.append(member)
                candidates.sort(key=lambda member:(Path(member.name).suffix.lower() not in {".txt",".log",".csv"},member.name.lower()))
                for member in candidates:
                    stream=packed.extractfile(member)
                    if stream is None:
                        continue
                    with stream:
                        candidate=stream.read(limit+1)
                    if len(candidate)>limit:
                        raise ValueError("El log descomprimido excede el límite permitido")
                    try:
                        return _unpack_log_bytes(candidate,limit,depth+1)
                    except ValueError:
                        continue
                raise ValueError("El paquete GZ no contiene un log de texto")
        except (tarfile.TarError,EOFError):
            # A .gz may contain a single text stream rather than a tar archive.
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data),mode="rb") as packed_text:
                    unpacked=packed_text.read(limit+1)
            except (OSError,EOFError) as exc:
                raise ValueError("No se pudo descomprimir el archivo GZ") from exc
            if len(unpacked)>limit:
                raise ValueError("El log descomprimido excede el límite permitido")
            return _unpack_log_bytes(unpacked,limit,depth+1)
    if len(data)>limit:
        raise ValueError("El log excede el límite permitido")
    if not _is_log_text(data):
        raise ValueError("El contenido no es texto legible; no se mostrará como caracteres corruptos")
    return data

def _tar_gz_text_members(path:Path)->list[tuple[str,str,bytes]]:
    """Read safe text members from Hillstone BDS tar.gz exports."""
    members=[]
    total=0
    try:
        with tarfile.open(path,mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                name=member.name.replace("\\","/")
                parts=Path(name).parts
                if not name or name.startswith("/") or ".." in parts or Path(name).is_absolute() or (parts and parts[0].endswith(":")):
                    raise ValueError("El TAR.GZ contiene una ruta insegura")
                suffix=Path(name).suffix.lower()
                if suffix not in {".txt",".log",".csv",".gz",".tgz"}:
                    continue
                if member.size<0 or member.size>MAX_FILE:
                    raise ValueError("Un log del TAR.GZ excede el límite de 512 MiB")
                total+=member.size
                if total>MAX_UNZIPPED:
                    raise ValueError("El TAR.GZ excede el límite descomprimido")
                stream=archive.extractfile(member)
                if stream is None:
                    raise ValueError("No se pudo leer un log dentro del TAR.GZ")
                with stream:
                    content=stream.read(MAX_FILE+1)
                if len(content)!=member.size or len(content)>MAX_FILE:
                    raise ValueError("El tamaño de un log del TAR.GZ no coincide con su encabezado")
                try:
                    content=_unpack_log_bytes(content,MAX_FILE)
                except ValueError:
                    # Keep only actual text exports; the original TAR.GZ is
                    # preserved in the bundle as the source evidence.
                    continue
                output_suffix=suffix if suffix in {".txt",".log",".csv"} else ".txt"
                members.append((Path(name).name,output_suffix,content))
    except (tarfile.TarError,OSError,EOFError) as exc:
        raise ValueError("La descarga no contiene un TAR.GZ válido") from exc
    if not members:
        raise ValueError("El TAR.GZ no contiene archivos TXT, LOG o CSV para visualizar")
    return members

def _packed_gzip_archive(name:str,data:bytes)->zipfile.ZipFile:
    """Expose safe text members from gzip/tar.gz as a temporary virtual ZIP."""
    if len(data)>MAX_FILE: raise HTTPException(413,"El archivo GZ supera el límite de 512 MiB")
    extracted:list[tuple[str,bytes]]=[]
    total=0
    try:
        try:
            with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as packed:
                for member in packed.getmembers():
                    if not member.isfile(): continue
                    normalized=member.name.replace("\\","/")
                    parts=Path(normalized).parts
                    if not normalized or normalized.startswith("/") or ".." in parts or Path(normalized).is_absolute() or (parts and parts[0].endswith(":")):
                        raise ValueError("El TAR.GZ contiene una ruta insegura")
                    suffix=Path(normalized).suffix.lower()
                    if suffix not in {".txt",".log",".csv",".gz",".tgz"}: continue
                    if member.size<0 or member.size>MAX_FILE: raise ValueError("Un archivo del TAR.GZ supera el límite permitido")
                    total+=member.size
                    if total>MAX_UNZIPPED: raise ValueError("El TAR.GZ excede el límite descomprimido")
                    stream=packed.extractfile(member)
                    if stream is None: continue
                    with stream: raw=stream.read(MAX_FILE+1)
                    if len(raw)>MAX_FILE: raise ValueError("Un archivo del TAR.GZ supera el límite permitido")
                    try: text_bytes=_unpack_log_bytes(raw,MAX_FILE)
                    except ValueError: continue
                    filename=Path(normalized).name
                    if suffix in {".gz",".tgz"}: filename=Path(filename).stem+".txt"
                    extracted.append((filename,_decode(text_bytes).encode("utf-8-sig")))
        except (tarfile.TarError,EOFError,OSError):
            # Plain .gz files contain one compressed stream rather than a TAR.
            with gzip.GzipFile(fileobj=io.BytesIO(data),mode="rb") as packed_text:
                raw=packed_text.read(MAX_FILE+1)
            if len(raw)>MAX_FILE: raise ValueError("El GZ descomprimido excede el límite permitido")
            text_bytes=_unpack_log_bytes(raw,MAX_FILE)
            filename=Path(name).name
            lower=filename.lower()
            if lower.endswith(".tar.gz"): filename=filename[:-7]+".txt"
            elif lower.endswith(".tgz"): filename=filename[:-4]+".txt"
            elif lower.endswith(".gz"): filename=filename[:-3] or "log.txt"
            if Path(filename).suffix.lower() not in {".txt",".log",".csv"}: filename+=".txt"
            extracted.append((filename,_decode(text_bytes).encode("utf-8-sig")))
    except (OSError,EOFError,gzip.BadGzipFile,ValueError) as exc:
        raise HTTPException(400,"No se pudo descomprimir o validar el archivo GZ") from exc
    if not extracted: raise HTTPException(415,"El paquete GZ no contiene logs de texto visualizables")
    buffer=io.BytesIO()
    used:set[str]=set()
    try:
        with zipfile.ZipFile(buffer,mode="w",compression=zipfile.ZIP_DEFLATED) as virtual:
            for filename,content in extracted:
                candidate=filename;counter=2
                while candidate.lower() in used:
                    stem=Path(filename).stem;suffix=Path(filename).suffix
                    candidate=f"{stem}_{counter}{suffix}";counter+=1
                used.add(candidate.lower())
                virtual.writestr(candidate,content)
        buffer.seek(0)
        return zipfile.ZipFile(buffer,mode="r")
    except (OSError,zipfile.BadZipFile) as exc:
        buffer.close()
        raise HTTPException(400,"No se pudo preparar la navegación del paquete GZ") from exc

def archive_at_path(root:zipfile.ZipFile,entry_path:str):
    if not entry_path or len(entry_path)>63 or len(entry_path.split("."))>8 or any(not part.isdigit() for part in entry_path.split(".")): raise HTTPException(422,"Ruta interna de ZIP inválida")
    current=root
    try:
        for raw_index in entry_path.split("."):
            index=int(raw_index);items=current.infolist()
            if index>=len(items): raise HTTPException(404,"Archivo dentro del ZIP no encontrado")
            item=items[index]
            if item.is_dir(): raise HTTPException(415,"La ruta seleccionada no es un paquete")
            if item.file_size>MAX_FILE: raise HTTPException(413,"El ZIP interno supera el límite de 512 MiB")
            content=current.read(item)
            current.close()
            is_zip=content.startswith((b"PK\x03\x04",b"PK\x05\x06",b"PK\x07\x08"))
            if Path(item.filename).suffix.lower()==".zip" or is_zip:
                current=zipfile.ZipFile(io.BytesIO(content))
                validate_archive(current)
            elif content.startswith(b"\x1f\x8b"):
                current=_packed_gzip_archive(item.filename,content)
            else:
                raise HTTPException(415,"El elemento interno no es ZIP, GZ ni TAR.GZ")
        return current
    except HTTPException:
        current.close()
        raise
    except (OSError,ValueError,RuntimeError,zipfile.BadZipFile) as exc:
        current.close()
        raise HTTPException(400,"No se pudo abrir o validar el ZIP interno") from exc

@app.get("/api/backups/{backup_id}/contents")
def backup_contents(backup_id:int,db:Session=Depends(get_db)):
    row,_path,archive=verified_backup_archive(backup_id,db)
    try:
        return {"backup_id":row.id,"filename":row.filename,"entries":list_archive_entries(archive)}
    finally: archive.close()

def list_archive_entries(archive:zipfile.ZipFile):
    entries=[]
    for index,item in enumerate(archive.infolist()):
        if item.is_dir(): continue
        ext=Path(item.filename).suffix.lower()
        packed_text=False
        packed_zip=False
        # Hillstone occasionally gives compressed logs a .txt/.csv name (or
        # another misleading suffix). Detect gzip by its bytes so the viewer
        # offers package navigation instead of rendering compressed bytes.
        if item.file_size>=2:
            try:
                with archive.open(item) as stream:
                    signature=stream.read(4)
                    packed_text=signature.startswith(b"\x1f\x8b")
                    packed_zip=signature.startswith((b"PK\x03\x04",b"PK\x05\x06",b"PK\x07\x08"))
            except (RuntimeError,zipfile.BadZipFile):
                packed_text=False
        is_archive=ext==".zip" or packed_zip or packed_text
        packed_type="tar.gz" if packed_text else "zip" if packed_zip else None
        entries.append({"index":index,"name":Path(item.filename).name,"size_bytes":item.file_size,
            "viewable":ext in {".txt",".csv",".log",".png"} or is_archive,
            "is_image":ext==".png" and not is_archive,"is_archive":is_archive,
            "packed_text":packed_text,"packed_type":packed_type})
    return entries

@app.get("/api/backups/{backup_id}/archives/{entry_path}")
def backup_nested_contents(backup_id:int,entry_path:str,db:Session=Depends(get_db)):
    row,_path,root=verified_backup_archive(backup_id,db)
    try:
        archive=archive_at_path(root,entry_path)
        try: return {"backup_id":row.id,"filename":row.filename,"entries":list_archive_entries(archive)}
        finally: archive.close()
    finally:
        if not root.fp is None: root.close()

@app.get("/api/backups/{backup_id}/entries/{entry_path}")
def backup_content(backup_id:int,entry_path:str,db:Session=Depends(get_db)):
    _row,_path,archive=verified_backup_archive(backup_id,db)
    try:
        parts=entry_path.split(".")
        if not entry_path or len(parts)>8 or any(not part.isdigit() for part in parts): raise HTTPException(422,"Ruta interna inválida")
        if len(parts)>1:
            parent=archive_at_path(archive,".".join(parts[:-1]))
            archive.close();archive=parent
        index=int(parts[-1]);items=archive.infolist()
        if index>=len(items): raise HTTPException(404,"Log dentro del ZIP no encontrado")
        item=items[index]
        ext=Path(item.filename).suffix.lower()
        if item.is_dir(): raise HTTPException(415,"Este elemento no es compatible con el visor")
        if ext==".png":
            if item.file_size>10*1024*1024: raise HTTPException(413,"La captura supera el límite de visualización de 10 MiB")
            try: content=archive.read(item)
            except (RuntimeError,zipfile.BadZipFile) as exc: raise HTTPException(400,"No se pudo leer la captura dentro del ZIP") from exc
            if not content.startswith(b"\x89PNG\r\n\x1a\n"): raise HTTPException(400,"El archivo no contiene una imagen PNG válida")
            return {"name":Path(item.filename).name,"media_type":"image/png","image_data":base64.b64encode(content).decode("ascii")}
        if ext not in {".txt",".csv",".log",".gz",".tgz"}:
            try:
                with archive.open(item) as stream: is_gzip=stream.read(2)==b"\x1f\x8b"
            except (RuntimeError,zipfile.BadZipFile) as exc:
                raise HTTPException(400,"No se pudo identificar el log dentro del ZIP") from exc
            if not is_gzip: raise HTTPException(415,"Este elemento no es compatible con el visor")
        max_viewer_bytes=64*1024*1024
        if item.file_size>max_viewer_bytes: raise HTTPException(413,"El archivo supera el límite de lectura del visor de 64 MiB")
        try:
            with archive.open(item) as stream: content_bytes=stream.read(max_viewer_bytes+1)
        except (RuntimeError,zipfile.BadZipFile) as exc: raise HTTPException(400,"No se pudo leer el log dentro del ZIP") from exc
        if len(content_bytes)>max_viewer_bytes: raise HTTPException(413,"El archivo supera el límite de lectura del visor de 64 MiB")
        try: content_bytes=_unpack_log_bytes(content_bytes,max_viewer_bytes)
        except ValueError as exc:
            message=str(exc)
            status=413 if "excede el límite" in message else 415
            raise HTTPException(status,message) from exc
        try:
            if content_bytes.startswith((b"\xff\xfe",b"\xfe\xff")):
                content=content_bytes.decode("utf-16")
            else:
                content=_decode(content_bytes)
        except (UnicodeDecodeError,RuntimeError,zipfile.BadZipFile) as exc: raise HTTPException(400,"No se pudo decodificar el log dentro del ZIP") from exc
        return {"name":Path(item.filename).name,"content":content}
    finally: archive.close()

@app.get("/api/backups/{backup_id}/internal-file")
def backup_internal_file(backup_id:int,db:Session=Depends(get_db)):
    row,_path,archive=verified_backup_archive(backup_id,db);archive.close()
    return {"path":row.stored_path,"filename":row.filename}

@app.get("/api/backups/{backup_id}/analysis")
def analyze_registered_firewall_backup(backup_id:int,db:Session=Depends(get_db)):
    row,path,verified=verified_backup_archive(backup_id,db);verified.close()
    device=db.get(Device,row.device_id)
    if not device or device.kind!="FIREWALL": raise HTTPException(422,"El analizador inicial solo admite respaldos del firewall")
    try:
        result=analyze_firewall_zip(path)
    except (OSError,ValueError,zipfile.BadZipFile) as exc:
        raise HTTPException(400,str(exc)) from exc
    return {"backup":{"id":row.id,"device_id":row.device_id,"device_name":device.name,"filename":row.filename,"created_at":row.created_at.isoformat(),"sha256":row.sha256},**result}

@app.post("/api/backups/import")
def import_backup(body:dict,db:Session=Depends(get_db)):
    device_id=body.get("device_id"); source=body.get("path")
    if not isinstance(device_id,int) or not isinstance(source,str): raise HTTPException(422,"Se requiere dispositivo y archivo")
    device=db.get(Device,device_id)
    if not device: raise HTTPException(404,"Dispositivo no encontrado")
    try:
        src=Path(source).resolve(strict=True); fmt,digest,size=inspect_file(src)
    except (OSError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
    date=datetime.now(timezone.utc); target_dir=configured_backup_dir(db) / str(device_id) / date.strftime("%Y-%m-%d");target_dir.mkdir(parents=True,exist_ok=True)
    target=target_dir / f"{digest[:12]}_{src.name}"
    duplicate=db.query(Backup).filter_by(device_id=device_id,sha256=digest).first() is not None
    if not target.exists(): shutil.copyfile(src,target)
    row=Backup(device_id=device_id,filename=src.name,stored_path=str(target),format=fmt,sha256=digest,size_bytes=size,duplicate=duplicate)
    db.add(row);db.commit();db.refresh(row);audit(db,"backup.import",f"device={device_id} sha256={digest}")
    return manifest([row])[0]

@app.get("/api/backups/manifest")
def backup_manifest(db:Session=Depends(get_db)):
    return JSONResponse(manifest(db.query(Backup).order_by(Backup.created_at.desc()).all()),headers={"Content-Disposition":"attachment; filename=som-backup-manifest.json"})

@app.post("/api/backups/internal/firewall-bundle")
def create_firewall_bundle(body:BackupBundleIn,db:Session=Depends(get_db)):
    device=db.get(Device,body.device_id)
    if not device or device.kind not in {"FIREWALL","WAF","BDS"}: raise HTTPException(404,"Dispositivo Hillstone no encontrado")
    run_dirs=set()
    checked=[]
    total_bytes=0
    try:
        for item in body.files:
            raw_path=Path(item.path)
            if raw_path.is_symlink(): raise ValueError("La descarga no puede ser un enlace simbólico")
            path=raw_path.resolve(strict=True)
            if not path.is_file(): raise ValueError("La descarga no es un archivo regular")
            if not path.is_relative_to(AUTOMATION_STAGING_DIR.resolve()): raise ValueError("Archivo fuera del área temporal de automatización")
            if item.format=="PNG":
                with path.open("rb") as image_file: signature=image_file.read(8)
                if path.suffix.lower()!=".png" or signature!=b"\x89PNG\r\n\x1a\n": raise ValueError("La evidencia debe ser una captura PNG válida")
            run_dirs.add(path.parent)
            if path.stat().st_size>MAX_FILE: raise ValueError("Archivo excede 512 MiB")
            total_bytes+=path.stat().st_size
            if total_bytes>2*1024*1024*1024: raise ValueError("La ejecución excede el máximo de 2 GiB")
            checked.append((item,path))
    except (OSError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
    if len(run_dirs)!=1: raise HTTPException(400,"Todos los archivos deben pertenecer a la misma ejecución")
    formats_by_category={}
    for item,_path in checked: formats_by_category.setdefault(item.category,set()).add(item.format)
    expected=(
        {"EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","THREATLOG","SESSIONLOG","NATLOG","URLLOG"}
        if device.kind=="FIREWALL"
        else {"EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","NATLOG","WEBACCESSLOG","NETWORKSECURITYLOG","WEBSECURITYLOG"}
        if device.kind=="WAF"
        else {"THREATLOG","EVENTLOG","NETWORKLOG","CONFIGURATIONLOG","SESSIONLOG"}
    )
    valid_category_formats=lambda formats: formats=={"PNG"} or bool(formats) and formats<={"TXT","CSV","ZIP"} or device.kind=="BDS" and formats=={"TAR_GZ"}
    if set(formats_by_category)!=expected or any(not valid_category_formats(formats) for formats in formats_by_category.values()):
        raise HTTPException(400,"Cada categoría debe incluir sus exportaciones, un ZIP de logs o una captura PNG de consulta sin registros")
    report_date=body.report_date
    date_folder=datetime.strptime(report_date,"%d_%m_%Y").strftime("%Y-%m-%d")
    output_dir=configured_backup_dir(db)/str(device.id)/date_folder
    output_dir.mkdir(parents=True,exist_ok=True)
    prefix={"FIREWALL":"FW","WAF":"WAF","BDS":"BDS"}[device.kind]
    target=output_dir/f"{prefix}_LOGS_{report_date}.zip"
    # Stage each run beside the canonical archive, then atomically replace it
    # only after the new ZIP has been written and verified.
    temp_target=output_dir/f".{target.stem}.{secrets.token_hex(8)}.tmp.zip"
    previous_target=output_dir/f".{target.name}.{secrets.token_hex(8)}.previous"
    entries=[]
    used_names=set()
    output_archive=None
    native_csv_categories={item.category for item,_path in checked if item.format=="CSV"}
    try:
        output_archive=zipfile.ZipFile(temp_target,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6)
        with output_archive as archive:
            for item,path in checked:
                arcname=path.name
                if arcname in used_names: raise ValueError("Nombre de archivo duplicado dentro del paquete")
                used_names.add(arcname)
                digest=inspect_file(path)[1]
                archive.write(path,arcname=arcname)
                entries.append({"category":item.category,"format":item.format,"filename":arcname,"size_bytes":path.stat().st_size,"sha256":digest,"evidence":item.format=="PNG"})
                if item.format=="TAR_GZ":
                    for member_index,(member_name,suffix,member_bytes) in enumerate(_tar_gz_text_members(path),start=1):
                        # Normalize encodings before adding files so the viewer
                        # can decode BDS exports consistently as UTF-8.
                        text_bytes=_decode(member_bytes).encode("utf-8-sig")
                        stem=Path(member_name).stem
                        extracted_name=f"{prefix}_{item.category}_{report_date}_{stem}{suffix}"
                        if extracted_name in used_names:
                            extracted_name=f"{prefix}_{item.category}_{report_date}_{stem}_{member_index}{suffix}"
                        if extracted_name in used_names: raise ValueError("Nombre de log extraído duplicado dentro del paquete")
                        if len(text_bytes)>MAX_FILE: raise ValueError("El log extraído del TAR.GZ excede 512 MiB")
                        used_names.add(extracted_name)
                        archive.writestr(extracted_name,text_bytes)
                        entry={"category":item.category,"format":suffix.lstrip(".").upper(),"filename":extracted_name,"size_bytes":len(text_bytes),"sha256":hashlib.sha256(text_bytes).hexdigest(),"evidence":False,"extracted_from":arcname}
                        entries.append(entry)
                        if device.kind=="FIREWALL" and suffix==".txt" and item.category not in native_csv_categories:
                            try: csv_bytes=_txt_export_to_csv(text_bytes,item.category)
                            except ValueError: csv_bytes=None
                            if csv_bytes is not None:
                                csv_name=f"{prefix}_{item.category}_{report_date}_CSV_LOCAL.csv"
                                if csv_name in used_names: csv_name=f"{prefix}_{item.category}_{report_date}_CSV_LOCAL_{member_index}.csv"
                                if csv_name in used_names: raise ValueError("Nombre de CSV convertido duplicado dentro del paquete")
                                if len(csv_bytes)>MAX_FILE: raise ValueError("El CSV convertido excede 512 MiB")
                                used_names.add(csv_name)
                                archive.writestr(csv_name,csv_bytes)
                                entries.append({"category":item.category,"format":"CSV","filename":csv_name,"size_bytes":len(csv_bytes),"sha256":hashlib.sha256(csv_bytes).hexdigest(),"evidence":False,"converted_from":extracted_name})
                if device.kind=="FIREWALL" and item.format=="TXT" and item.category not in native_csv_categories:
                    csv_bytes=_txt_export_to_csv(_txt_export_bytes(path),item.category)
                    csv_name=f"{prefix}_{item.category}_{report_date}_CSV_LOCAL.csv"
                    if csv_name in used_names: raise ValueError("Nombre de CSV convertido duplicado dentro del paquete")
                    if len(csv_bytes)>MAX_FILE: raise ValueError("El CSV convertido excede 512 MiB")
                    used_names.add(csv_name)
                    archive.writestr(csv_name,csv_bytes)
                    entries.append({"category":item.category,"format":"CSV","filename":csv_name,"size_bytes":len(csv_bytes),"sha256":hashlib.sha256(csv_bytes).hexdigest(),"evidence":False,"converted_from":"TXT"})
            archive.writestr("MANIFEST.json",json.dumps({"device":device.name,"date":report_date,"files":entries},ensure_ascii=False,indent=2))
    except (OSError,ValueError,zipfile.BadZipFile) as exc:
        temp_target.unlink(missing_ok=True)
        raise HTTPException(400,"No se pudo crear el paquete ZIP de respaldos") from exc
    try: fmt,digest,size=inspect_file(temp_target)
    except (OSError,ValueError) as exc:
        temp_target.unlink(missing_ok=True);raise HTTPException(500,"Falló la verificación SHA-256 del paquete") from exc

    row=db.query(Backup).filter_by(device_id=device.id,filename=target.name,stored_path=str(target)).order_by(Backup.created_at.desc()).first()
    old_row_values=None
    if row is not None:
        old_row_values=(row.stored_path,row.format,row.sha256,row.size_bytes,row.duplicate,row.integrity_valid,row.created_at)
    duplicate_query=db.query(Backup).filter_by(device_id=device.id,sha256=digest)
    if row is not None: duplicate_query=duplicate_query.filter(Backup.id != row.id)
    duplicate=duplicate_query.first() is not None
    had_target=target.exists()
    try:
        if had_target: os.replace(target,previous_target)
        os.replace(temp_target,target)
        if row is None:
            row=Backup(device_id=device.id,filename=target.name,stored_path=str(target),format=fmt,sha256=digest,size_bytes=size,duplicate=duplicate)
            db.add(row)
        else:
            row.stored_path=str(target);row.format=fmt;row.sha256=digest;row.size_bytes=size
            row.duplicate=duplicate;row.integrity_valid=True;row.created_at=datetime.now(timezone.utc)
        db.commit();db.refresh(row)
    except Exception as exc:
        db.rollback()
        target.unlink(missing_ok=True)
        if had_target and previous_target.exists(): os.replace(previous_target,target)
        temp_target.unlink(missing_ok=True)
        if old_row_values is not None:
            (row.stored_path,row.format,row.sha256,row.size_bytes,row.duplicate,row.integrity_valid,row.created_at)=old_row_values
        raise HTTPException(500,"No se pudo actualizar el registro del respaldo") from exc
    previous_target.unlink(missing_ok=True)
    audit(db,"backup.firewall.bundle",f"device={device.id} items={len(entries)} sha256={digest}")
    return {"backup":manifest([row])[0],"file_count":len(entries),"files":entries,"path":str(target)}

@app.get("/api/activities")
def activities(db:Session=Depends(get_db)):
    return [{"id":a.id,"occurred_at":a.occurred_at.isoformat(),"category":a.category,"device_id":a.device_id,"description":a.description,"status":a.status,"requester":a.requester,"approver":a.approver,"notes":a.notes} for a in db.query(Activity).order_by(Activity.occurred_at.desc()).limit(500)]

@app.post("/api/activities")
def add_activity(body:ActivityIn,db:Session=Depends(get_db)):
    if body.device_id and not db.get(Device,body.device_id): raise HTTPException(404,"Dispositivo no encontrado")
    a=Activity(**body.model_dump());db.add(a);db.commit();db.refresh(a);audit(db,"activity.create",body.category)
    return {"id":a.id,"occurred_at":a.occurred_at.isoformat(),**body.model_dump()}

@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db)):
    today=datetime.now(timezone.utc).date(); start=datetime.combine(today,datetime.min.time(),tzinfo=timezone.utc)
    latest=db.query(Backup).order_by(Backup.created_at.desc()).first()
    return {"devices_total":db.query(Device).filter_by(enabled=True).count(),"devices_online":db.query(ConnectivityCheck.device_id).filter(ConnectivityCheck.checked_at>=start,ConnectivityCheck.success.is_(True)).distinct().count(),"backups_today":db.query(Backup).filter(Backup.created_at>=start).count(),"activities_today":db.query(Activity).filter(Activity.occurred_at>=start).count(),"backup_failures":None,"events_processed":None,"vpn_status":"unknown","last_backup":latest.created_at.isoformat() if latest else None}

@app.get("/api/audit")
def audit_history(db:Session=Depends(get_db)):
    return [{"id":a.id,"occurred_at":a.occurred_at.isoformat(),"action":a.action,"detail":a.detail} for a in db.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(200)]

import hashlib
import json
import zipfile
from pathlib import Path

ALLOWED = {"CSV", "JSON", "TXT", "LOG", "XLSX", "ZIP"}
MAX_FILE = 512 * 1024 * 1024
MAX_UNZIPPED = 1024 * 1024 * 1024

def inspect_file(path: Path) -> tuple[str, str, int]:
    if not path.is_file() or path.is_symlink(): raise ValueError("El archivo no es válido")
    size = path.stat().st_size
    if size > MAX_FILE: raise ValueError("El archivo excede el límite de 512 MiB")
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): digest.update(block)
    ext = path.suffix.lower().lstrip(".")
    if ext == "xlsx" and zipfile.is_zipfile(path): fmt = "XLSX"
    elif ext == "zip" and zipfile.is_zipfile(path): fmt = "ZIP"
    elif ext in {"csv", "json", "txt", "log"}: fmt = ext.upper()
    else: fmt = "UNKNOWN"
    if fmt == "ZIP":
        with zipfile.ZipFile(path) as archive:
            total = 0
            for item in archive.infolist():
                member = Path(item.filename)
                if member.is_absolute() or ".." in member.parts or item.filename.startswith(("/", "\\")):
                    raise ValueError("ZIP rechazado: contiene una ruta insegura")
                total += item.file_size
                if total > MAX_UNZIPPED: raise ValueError("ZIP excede el límite de tamaño descomprimido")
                if item.file_size and item.compress_size == 0: raise ValueError("ZIP inválido")
                if item.compress_size and item.file_size / item.compress_size > 1000: raise ValueError("ZIP excede la relación de compresión permitida")
    return fmt, digest.hexdigest(), size

def manifest(rows):
    return [{"id": r.id, "device_id": r.device_id, "filename": r.filename, "format": r.format, "sha256": r.sha256, "size_bytes": r.size_bytes, "created_at": r.created_at.isoformat(), "duplicate": r.duplicate} for r in rows]

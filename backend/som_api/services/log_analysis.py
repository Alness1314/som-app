"""Parse the CSV/TXT exports produced by the supported Hillstone A2700 logs."""
from __future__ import annotations

import csv
import hashlib
import io
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .files import MAX_FILE, MAX_UNZIPPED

CATEGORIES = {
    "EVENTLOG": "Event Log",
    "NETWORKLOG": "Network Log",
    "CONFIGURATIONLOG": "Configuration Log",
    "THREATLOG": "Threat Log",
    "SESSIONLOG": "Session Log",
    "NATLOG": "NAT Log",
    "URLLOG": "URL Log",
}
IP = r"(?:\d{1,3}\.){3}\d{1,3}"
TIMESTAMP_FORMATS = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")


def _category(names: list[str]) -> str | None:
    value = " ".join(names).upper().replace("_", "")
    for key in CATEGORIES:
        if key in value:
            return key
    return None


def _timestamp(value: str) -> tuple[str, datetime | None]:
    value = value.strip().strip('"')
    for fmt in TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.isoformat(sep=" "), parsed
        except ValueError:
            continue
    return value, None


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _parse_csv(data: bytes, category: str) -> list[tuple[str, str, str]]:
    rows = list(csv.reader(io.StringIO(_decode(data), newline="")))
    if not rows:
        return []
    has_header = [v.strip().lower() for v in rows[0][:3]] == ["time", "level", "message"]
    if has_header:
        rows = rows[1:]
    result = []
    for row in rows:
        if len(row) < 2 or not row[0].strip():
            continue
        if has_header or (category == "THREATLOG" and len(row) >= 3):
            level = row[1].strip() if len(row) > 1 else ""
            message = ",".join(row[2:]).strip() if len(row) > 2 else ""
        else:
            level = ""
            message = ",".join(row[1:]).strip()
        result.append((row[0].strip(), level, message))
    return result


def _parse_txt(data: bytes, category: str) -> list[tuple[str, str, str]]:
    lines = _decode(data).splitlines()
    if lines and [v.strip().lower() for v in lines[0].split(",", 2)] == ["time", "level", "message"]:
        lines = lines[1:]
    table = category in {"EVENTLOG", "NETWORKLOG", "CONFIGURATIONLOG", "THREATLOG"}
    result = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split(",", 2 if table else 1)
        if len(parts) < 2:
            continue
        if table and len(parts) == 3:
            result.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
        else:
            result.append((parts[0].strip(), "", ",".join(parts[1:]).strip()))
    return result


def _field(pattern: str, message: str, flags: int = re.IGNORECASE) -> str | None:
    match = re.search(pattern, message, flags)
    return match.group(1).strip().strip('"') if match else None


def _normalize(category: str, timestamp: str, level: str, message: str, source: str, fmt: str) -> dict:
    normalized_time, parsed_time = _timestamp(timestamp)
    source_ip = _field(rf"\bsrcip\s+({IP})", message) or _field(rf"\bsource\s+ip\s*:?\s*({IP})", message) or _field(rf"\bfrom\s+({IP})(?::\d+)?", message)
    destination_ip = _field(rf"\bdstip\s+({IP})", message) or _field(rf"\bdestination\s+ip\s*:?\s*({IP})", message) or _field(rf"\bto\s+({IP})(?::\d+)?", message)
    if category == "URLLOG":
        source_ip = source_ip or _field(rf"\bIP\s+({IP})", message)
    action = _field(r"\baction\s*:?[ \t]*([a-z][a-z _-]*?)(?=,|;|$)", message)
    if not action and category == "SESSIONLOG":
        action = _field(r"\b(policy deny|session start|session end)\b", message)
    severity = _field(r"\bthreat severity\s*:\s*([^,;]+)", message) or (level.strip() or None)
    username = _field(r"\b(?:administrator|admin user|user)\s+['\"]?([^,'\".]+)", message)
    if category == "CONFIGURATIONLOG":
        username = _field(r"^['\"]?([^'\"@,]+)['\"]?@webui", message)
    url = _field(r"\bURL\s+(https?://[^,\s]+)", message)
    protocol = _field(r"\bprotocol\s*:?[ \t]*([a-z0-9_-]+)", message)
    source_port = _field(r"\bsrcport\s+(\d+)", message) or (_field(rf"\bIP\s+{IP}:(\d+)", message) if category == "URLLOG" else None)
    destination_port = _field(r"\bdstport\s+(\d+)", message)
    policy_id = _field(r"\bpolicy(?:id|\s+id)\s*:?\s*(\d+)", message)
    nat_type = _field(r"\bnattype\s+([a-z]+)", message)
    return {
        "timestamp": normalized_time,
        "epoch": parsed_time.timestamp() if parsed_time else None,
        "category": category,
        "category_name": CATEGORIES[category],
        "level": (severity if category == "THREATLOG" else level.strip()) or severity or "Sin nivel",
        "severity": severity,
        "message": message.strip(),
        "source": source,
        "source_format": fmt.upper(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "action": action,
        "username": username,
        "url": url,
        "policy_id": policy_id,
        "nat_type": nat_type.upper() if nat_type else None,
    }


def _validate_members(archive: zipfile.ZipFile) -> None:
    total = 0
    for item in archive.infolist():
        member = Path(item.filename)
        if member.is_absolute() or ".." in member.parts or item.filename.startswith(("/", "\\")):
            raise ValueError("El ZIP contiene una ruta interna insegura")
        if (item.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("El ZIP contiene un enlace simbólico")
        total += item.file_size
        if total > MAX_UNZIPPED or item.file_size > MAX_FILE:
            raise ValueError("El contenido excede los límites permitidos para analizar")
        if item.file_size and not item.compress_size:
            raise ValueError("El ZIP contiene un elemento inválido")
        if item.compress_size and item.file_size / item.compress_size > 1000:
            raise ValueError("El ZIP excede la relación de compresión permitida")


def analyze_firewall_zip(path: Path) -> dict:
    candidates: dict[str, list[tuple[str, str, bytes]]] = defaultdict(list)
    warnings: list[str] = []
    inflated_bytes = 0

    def walk(data: bytes, trail: list[str], depth: int) -> None:
        nonlocal inflated_bytes
        if depth > 8:
            warnings.append("Se omitió un ZIP que supera ocho niveles de anidamiento.")
            return
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            _validate_members(archive)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            warnings.append(f"No se pudo leer {' / '.join(trail) or path.name}: {exc}")
            return
        with archive:
            for item in archive.infolist():
                if inflated_bytes >= MAX_UNZIPPED:
                    return
                if item.is_dir():
                    continue
                inflated_bytes += item.file_size
                if inflated_bytes > MAX_UNZIPPED:
                    warnings.append("Se detuvo el análisis al alcanzar el límite total de contenido descomprimido (1 GiB).")
                    return
                name = Path(item.filename).name
                ext = Path(name).suffix.lower()
                if ext not in {".zip", ".csv", ".txt"}:
                    continue
                content = archive.read(item)
                if ext == ".zip":
                    walk(content, [*trail, name], depth + 1)
                    continue
                category = _category([*trail, name])
                if category is None:
                    # Standalone exports have distinctive message fields even if their ZIP label is generic.
                    sample = _decode(content[:8192]).lower()
                    category = next((key for marker, key in (("nattype", "NATLOG"), ("session start", "SESSIONLOG"), ("threat severity", "THREATLOG"), ("category ", "URLLOG")) if marker in sample), None)
                if category is None:
                    warnings.append(f"Se omitió {name}: no se pudo identificar su categoría.")
                    continue
                candidates[category].append((" / ".join([*trail, name]), ext[1:], content))

    try:
        walk(path.read_bytes(), [path.name], 0)
    except OSError as exc:
        raise ValueError("No se pudo leer el respaldo ZIP") from exc

    records: list[dict] = []
    category_file_info: dict[str, dict] = {}
    for category, files in candidates.items():
        csv_files = [item for item in files if item[1] == "csv"]
        selected = csv_files or [item for item in files if item[1] == "txt"]
        skipped_txt = len(files) - len(selected)
        if skipped_txt:
            warnings.append(f"{CATEGORIES[category]}: se priorizó CSV sobre {skipped_txt} TXT alternativo(s) para evitar duplicar exportaciones.")
        category_file_info[category] = {"files_used": len(selected), "alternate_txt_skipped": skipped_txt}
        seen: set[str] = set()
        for source, fmt, content in selected:
            parsed = _parse_csv(content, category) if fmt == "csv" else _parse_txt(content, category)
            for timestamp, level, message in parsed:
                if not timestamp or not message:
                    continue
                fingerprint = hashlib.sha256(f"{category}\0{timestamp.strip()}\0{level.strip()}\0{message.strip()}".encode("utf-8", "replace")).hexdigest()
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                records.append(_normalize(category, timestamp, level, message, source, fmt))

    records.sort(key=lambda row: row["epoch"] if row["epoch"] is not None else 0, reverse=True)
    capped = len(records) > 20000
    if capped:
        records = records[:20000]
        warnings.append("Se muestran como máximo 20,000 registros; el paquete contiene más.")

    category_counts = Counter(record["category"] for record in records)
    level_counts = Counter(record["level"] for record in records)
    failed_auth = [row for row in records if row["category"] == "EVENTLOG" and re.search(r"answer is failed|password error|login.{0,25}(?:fail|failed)|attempted to login.{0,50}failed", row["message"], re.I)]
    threats = [row for row in records if row["category"] == "THREATLOG"]
    denied_sessions = [row for row in records if row["category"] == "SESSIONLOG" and (row.get("action") or "").lower() == "policy deny"]
    blocked_urls = [row for row in records if row["category"] == "URLLOG" and (row.get("action") or "").lower() in {"block", "blocked", "deny", "drop"}]
    config_changes = [row for row in records if row["category"] == "CONFIGURATIONLOG"]
    findings = []
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in failed_auth:
        by_source[row["source_ip"] or "Origen no identificado"].append(row)
    for source, source_records in by_source.items():
        if len(source_records) >= 5:
            findings.append({"severity": "Alta" if len(source_records) >= 10 else "Media", "title": "Intentos de autenticación fallidos repetidos", "count": len(source_records), "detail": f"{len(source_records)} eventos de autenticación fallida; origen registrado: {source}.", "category": "EVENTLOG"})
    if threats:
        findings.append({"severity": "Alta" if any((row.get("severity") or "").lower() in {"high", "critical"} for row in threats) else "Media", "title": "Amenazas registradas por el firewall", "count": len(threats), "detail": "Conteo reportado por Threat Log; revisa acción, tipo y severidad en los registros.", "category": "THREATLOG"})
    if denied_sessions:
        findings.append({"severity": "Media", "title": "Sesiones denegadas por política", "count": len(denied_sessions), "detail": "El firewall registró sesiones con acción policy deny.", "category": "SESSIONLOG"})
    if blocked_urls:
        findings.append({"severity": "Media", "title": "Solicitudes URL bloqueadas", "count": len(blocked_urls), "detail": "URL Log registró acciones block, deny o drop.", "category": "URLLOG"})
    if config_changes:
        findings.append({"severity": "Informativa", "title": "Cambios de configuración registrados", "count": len(config_changes), "detail": "Configuration Log contiene cambios reportados por la consola.", "category": "CONFIGURATIONLOG"})

    dated = [datetime.fromtimestamp(row["epoch"]) for row in records if row["epoch"] is not None]
    for category, count in category_counts.items():
        if count == 1000:
            warnings.append(f"{CATEGORIES[category]} tiene exactamente 1,000 filas; podría haberse alcanzado el límite de exportación de la consola.")
    return {
        "record_count": len(records),
        "category_counts": [{"category": key, "name": CATEGORIES[key], "count": category_counts[key]} for key in CATEGORIES if category_counts[key]],
        "level_counts": [{"level": key, "count": value} for key, value in level_counts.most_common()],
        "findings": findings,
        "warnings": list(dict.fromkeys(warnings)),
        "range_start": min(dated).isoformat(sep=" ") if dated else None,
        "range_end": max(dated).isoformat(sep=" ") if dated else None,
        "files": [{"category": key, "name": CATEGORIES[key], **value} for key, value in category_file_info.items()],
        "records": records,
    }

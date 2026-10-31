from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, BigInteger, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def now_utc(): return datetime.now(timezone.utc)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    url: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_untrusted_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    checks: Mapped[list["ConnectivityCheck"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    credential: Mapped["DeviceCredential | None"] = relationship(back_populates="device", cascade="all, delete-orphan", uselist=False)

class DeviceCredential(Base):
    __tablename__ = "device_credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), unique=True, index=True)
    username_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    password_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)
    device: Mapped[Device] = relationship(back_populates="credential")

class ConnectivityCheck(Base):
    __tablename__ = "connectivity_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    tls_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    device: Mapped[Device] = relationship(back_populates="checks")

class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(12), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    integrity_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)

class Activity(Base):
    __tablename__ = "activities"
    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="Completada", index=True)
    requester: Mapped[str | None] = mapped_column(String(160), nullable=True)
    approver: Mapped[str | None] = mapped_column(String(160), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    detail: Mapped[str] = mapped_column(Text)

class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

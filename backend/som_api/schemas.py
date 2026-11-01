from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern="^(FIREWALL|WAF|BDS|OTHER)$")
    url: HttpUrl
    enabled: bool = True
    allow_untrusted_tls: bool = False
class DeviceOut(DeviceIn):
    id: int
    model_config = ConfigDict(from_attributes=True)
class DeviceCredentialsIn(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=4096)
    confirm_untrusted_tls: bool = False

    @field_validator("username")
    @classmethod
    def username_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El usuario no puede estar vacío")
        return value

class StorageSettingIn(BaseModel):
    destination_type: str = Field(pattern="^(local|nas|cloud_sync)$")
    path: str = Field(min_length=1, max_length=1024)

class BackupScheduleJobIn(BaseModel):
    kind: str = Field(pattern="^(FIREWALL|WAF|BDS)$")
    enabled: bool = False
    time: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    device_id: int = Field(gt=0)

class BackupScheduleIn(BaseModel):
    jobs: list[BackupScheduleJobIn] = Field(min_length=3, max_length=3)

class BackupDeleteIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason")
    @classmethod
    def reason_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("El motivo debe tener al menos 3 caracteres")
        return value

class BackupScheduleClaimIn(BaseModel):
    kind: str = Field(pattern="^(FIREWALL|WAF|BDS)$")
    run_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")

class BackupScheduleFinishIn(BackupScheduleClaimIn):
    success: bool
    message: str | None = Field(default=None, max_length=2000)

class BackupBundleItemIn(BaseModel):
    path: str = Field(min_length=1, max_length=2048)
    category: str = Field(pattern="^(EVENTLOG|NETWORKLOG|CONFIGURATIONLOG|THREATLOG|SESSIONLOG|NATLOG|URLLOG|WEBACCESSLOG|NETWORKSECURITYLOG|WEBSECURITYLOG)$")
    format: str = Field(pattern="^(TXT|CSV|ZIP|TAR_GZ|PNG)$")

class BackupBundleIn(BaseModel):
    device_id: int = Field(gt=0)
    report_date: str = Field(pattern="^\\d{2}_\\d{2}_\\d{4}$")
    files: list[BackupBundleItemIn] = Field(min_length=1, max_length=21)
class ActivityIn(BaseModel):
    category: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=10000)
    device_id: int | None = None
    status: str = Field(default="Completada", max_length=40)
    requester: str | None = Field(default=None, max_length=160)
    approver: str | None = Field(default=None, max_length=160)
    notes: str | None = Field(default=None, max_length=10000)
class ActivityOut(ActivityIn):
    id: int
    occurred_at: str

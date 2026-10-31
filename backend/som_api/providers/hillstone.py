from abc import ABC, abstractmethod

class HillstoneBackupProvider(ABC):
    """Contrato del proveedor; no se conocen selectores ni API de consola."""
    configured = False
    @abstractmethod
    async def check_connection(self): ...
    @abstractmethod
    async def authenticate(self): ...
    @abstractmethod
    async def navigate_to_logs(self): ...
    @abstractmethod
    async def configure_time_range(self, start, end): ...
    @abstractmethod
    async def export_logs(self, destination): ...
    @abstractmethod
    async def verify_download(self, path): ...

class UnconfiguredHillstoneProvider(HillstoneBackupProvider):
    def __init__(self, device_kind: str): self.device_kind = device_kind
    async def _unavailable(self): raise RuntimeError(f"Proveedor {self.device_kind} no configurado: validar UI, MFA y flujo autorizado.")
    async def check_connection(self): return await self._unavailable()
    async def authenticate(self): return await self._unavailable()
    async def navigate_to_logs(self): return await self._unavailable()
    async def configure_time_range(self, start, end): return await self._unavailable()
    async def export_logs(self, destination): return await self._unavailable()
    async def verify_download(self, path): return await self._unavailable()

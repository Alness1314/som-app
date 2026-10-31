# Arquitectura SOM

SOM corre como aplicación Electron local. El renderer React no tiene acceso Node; el preload expone una API mínima para HTTP local, selección de archivos y apertura HTTPS externa. El proceso principal genera puerto libre y token aleatorio en cada arranque, inicia FastAPI en `127.0.0.1` y detiene el backend al cerrar.

FastAPI valida el token en cada endpoint privado y rechaza clientes que no sean loopback. SQLite y SQLAlchemy guardan dispositivos, verificaciones, respaldos, actividades y auditoría. Los archivos importados se copian a almacenamiento administrado por dispositivo y fecha.

Paquetes backend: `som_api/models.py` (persistencia), `schemas.py` (validación), `services/files.py` (integridad y ZIP), `providers/` (contrato futuro de Hillstone) y `main.py` (API). Frontend: `App.tsx` y componentes de página; `api.ts` enlaza el preload.

La migración inicial está en Alembic. El arranque actual crea tablas faltantes desde los modelos; aplicar Alembic antes de habilitar cambios de esquema en producción.

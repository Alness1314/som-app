# Security Operations Manager (SOM)

Aplicación de escritorio local para organizar operaciones de seguridad. SOM combina Electron, React/TypeScript y un backend FastAPI/SQLite empaquetable para Windows. No requiere servicios propios en internet.

## Estado del MVP 0.1.0

Implementado: shell Electron seguro, navegación SOC, estado real de API, altas/edición/baja de dispositivos, verificaciones HTTPS con TLS estándar, registro de actividades, importación manual de respaldos, SHA-256, detección básica de extensiones, detección de duplicados, manifiesto JSON, límites/validaciones ZIP, auditoría local y persistencia SQLite.

Pendiente: generadores PDF/Excel, análisis normalizado de eventos, automatización de descargas, Programador de tareas, migración en ejecución, almacenaje Windows Credential Manager, instalador validado en Windows y cobertura de integración adicional. El proveedor Hillstone está explícitamente no configurado. No se usan selectores/endpoints inventados.

## Desarrollo

Requisitos para desarrollo: Node.js 22 y Python 3.12+. Ejecuta `scripts/setup.ps1`, luego `npm run dev`. La aplicación inicia FastAPI enlazado exclusivamente a `127.0.0.1` en puerto dinámico y autentica las llamadas con token aleatorio del proceso Electron. Los datos se guardan bajo `%APPDATA%\SOM\data` o rutas configuradas por entorno.

## Windows

Con dependencias instaladas, ejecuta `scripts/build.ps1`. Debe producir `release/SecurityOperationsManager-Setup-0.1.0.exe`. La distribución final aún necesita validación en una máquina Windows 11 limpia.

Consulta [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/BUILD_WINDOWS.md](docs/BUILD_WINDOWS.md), [docs/SECURITY.md](docs/SECURITY.md), [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) y [docs/TESTING.md](docs/TESTING.md).

Las especificaciones para trabajar con desarrollo guiado por especificaciones están en [docs/specs/README.md](docs/specs/README.md).

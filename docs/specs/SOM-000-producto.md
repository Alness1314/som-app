# SOM-000 — Producto y alcance del MVP

- Estado: Parcial
- Última revisión: 2026-10-15

## Objetivo

Proveer una estación Windows local para registrar actividades de ciberseguridad, gestionar configuración de activos y custodiar archivos de respaldo descargados manualmente.

## Alcance

El MVP usa Electron, React/TypeScript y FastAPI/Python con SQLite. No depende de un servidor propio ni publica una API en la red. La primera entrega prioriza infraestructura y respaldo manual; automatizaciones futuras requieren validación y autorización explícitas.

## Requisitos funcionales

- `SOM-000-01`: La interfaz ofrece Dashboard, Infraestructura, Respaldos, Análisis de logs, Reportes, Actividades, Historial y Configuración.
- `SOM-000-02`: Indicadores numéricos provienen de registros guardados; la falta de medición se presenta como desconocida/sin datos.
- `SOM-000-03`: Sophos, solicitudes, incidentes y TISAX se mantienen como extensiones futuras sin integraciones ficticias.
- `SOM-000-04`: El trabajo se divide por módulo y no se marca completo si no cumple sus criterios verificables.

## Criterios de aceptación

- [ ] Los módulos disponibles y pendientes están identificados en UI y documentación.
- [x] El dashboard obtiene conteos actuales de la base local y deja como desconocidos eventos y fallos no medidos.
- [ ] Las pantallas de análisis y reportes ejecutan flujos funcionales con archivos y datos reales/sintéticos.

## Verificación y pendientes

`npm test` compila frontend/Electron y ejecuta pruebas unitarias de archivos. Faltan pruebas de API/SQLite, análisis de eventos, reportes y empaquetado probado en Windows limpio.

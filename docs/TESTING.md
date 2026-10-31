# Pruebas

`scripts/test.ps1` construye el frontend/backend TypeScript y luego ejecuta pytest sobre pruebas sintéticas de hash, detección de extensión, rechazo de traversal ZIP y proveedor no configurado.

Las pruebas no requieren equipos reales. Añade pruebas de API con SQLite temporal/mocks, conectividad TLS simulada, duplicados, generación de PDF/XLSX y migración antes de release. `npm test` hoy hace typecheck y build; no implica pruebas funcionales completas.

# SOM-030 — Importación y custodia de respaldos

- Estado: Parcial
- Última revisión: 2026-10-15

## Requisitos

- `SOM-030-01`: Permitir seleccionar uno o más archivos descargados manualmente y asociarlos a un dispositivo.
- `SOM-030-02`: Guardar una copia original por dispositivo y fecha; calcular SHA-256 y conservar nombre, formato, tamaño y fecha de registro.
- `SOM-030-03`: Detectar CSV, JSON, TXT, LOG, XLSX y ZIP. No interpretar estructura desconocida ni desechar datos.
- `SOM-030-04`: Rechazar archivos que excedan límites y ZIP con rutas ascendentes, rutas absolutas o expansión excesiva. No extraer contenido sin necesidad.
- `SOM-030-05`: Identificar coincidencias de hash como posibles duplicados y exportar manifiesto.
- `SOM-030-06`: No presentar respaldo exitoso si el archivo no fue importado/validado.
- `SOM-030-07`: No iniciar descargas automáticas antes de validar proveedor Hillstone, UI y MFA.

## Criterios de aceptación

- [x] Selector de archivo, asociación y copia administrada desde la UI.
- [x] Hash SHA-256, extensiones iniciales, deduplicación por dispositivo y manifiesto JSON.
- [x] Inspección ZIP sin extracción y pruebas para traversal.
- [ ] Registrar intervalo temporal de cobertura cuando el formato lo permita y esté definido.
- [ ] Retención, búsqueda avanzada y detección de respaldos faltantes con calendario de operación acordado.
- [ ] Validar conservación/no sobrescritura en condiciones concurrentes.

## Dependencias

Para cobertura de tiempo hacen falta ejemplos sintéticos representativos o documentación del formato exportado de cada modelo Hillstone.

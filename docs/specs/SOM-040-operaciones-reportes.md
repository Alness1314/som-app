# SOM-040 — Actividades, análisis de logs y reportes

- Estado: Parcial
- Última revisión: 2026-10-15

## Requisitos

- `SOM-040-01`: Registrar actividad con fecha, categoría, dispositivo opcional, descripción, estado, solicitante, autorizador y notas.
- `SOM-040-02`: Mantener categorías iniciales acordadas y permitir consulta histórica.
- `SOM-040-03`: Normalizar eventos solo cuando las columnas/formato de origen sean conocidos; los campos no disponibles permanecen vacíos.
- `SOM-040-04`: Exportar eventos filtrados una vez implementados los parsers.
- `SOM-040-05`: Reporte diario PDF/Excel distingue sin eventos, sin datos disponibles y consulta fallida.
- `SOM-040-06`: No presentar ausencia de registros como ausencia de amenazas.

## Criterios de aceptación

- [x] API permite registrar y consultar actividades. La UI permite captura básica y listado.
- [ ] Formulario completo con evidencia, observaciones y estados editables.
- [ ] Importación/análisis normalizado de CSV/JSON con esquema identificado y sin asumir campos.
- [ ] Reporte PDF y Excel guardado con historial y valores derivados de SQLite.
- [ ] Pruebas de exportación, datos vacíos y fallos de consulta.

## Dependencias

Se necesitan ejemplos sintéticos o un contrato de log aprobado para cada parser, así como definición de métricas para reportes quincenales/mensuales.

# SOM-050 — Instalación y distribución Windows

- Estado: Especificado
- Última revisión: 2026-10-15

## Requisitos

- `SOM-050-01`: Generar instalador NSIS x64 llamado `SecurityOperationsManager-Setup-0.1.0.exe`.
- `SOM-050-02`: Empaquetar backend FastAPI con PyInstaller; usuario final no instala Python/Node.
- `SOM-050-03`: Scripts separados para setup de desarrollo, ejecución, pruebas, empaquetado de backend y NSIS.
- `SOM-050-04`: Mantener datos del usuario bajo AppData y respaldos en carpeta configurable.
- `SOM-050-05`: Validar instalación, inicio, cierre y persistencia en Windows 11 x64 limpio.

## Criterios de aceptación

- [x] Se definieron scripts PowerShell y electron-builder NSIS x64.
- [ ] Construir el backend PyInstaller en Python 3.12 con todas las dependencias del proyecto.
- [ ] Generar el instalador solicitado.
- [ ] Instalar y verificar el instalador en VM Windows 11 limpia sin Node/Python.
- [ ] Confirmar firma, rutas de datos, desinstalación y conservación de datos.

## Verificación

`npm test` no construye el instalador; `scripts/build.ps1` es el flujo de distribución. El empaquetado requiere toolchain Python/Node de desarrollo.

# SOM-010 — Aplicación de escritorio y seguridad local

- Estado: Parcial
- Última revisión: 2026-10-15

## Requisitos

- `SOM-010-01`: Electron lanza y termina el proceso FastAPI local.
- `SOM-010-02`: Backend escucha en loopback y puerto dinámico, y solicita un token aleatorio por proceso en cada ruta privada.
- `SOM-010-03`: `contextIsolation`, sandbox y `nodeIntegration: false` permanecen activos; preload expone operaciones limitadas.
- `SOM-010-04`: CSP restringe scripts, conexiones y recursos. Navegación exterior abre únicamente HTTPS en navegador del sistema.
- `SOM-010-05`: Los datos persisten bajo la carpeta de usuario de Windows o en rutas absolutas opcionales configuradas para desarrollo.
- `SOM-010-06`: No guardar credenciales reales ni registrar secretos.
- `SOM-010-07`: La interfaz se estiliza con Tailwind CSS y permite tema oscuro (predeterminado) y claro, conservando la preferencia local.

## Criterios de aceptación

- [x] Configuración principal de BrowserWindow restringe aislamiento, Node y sandbox.
- [x] FastAPI valida token y loopback, y Electron crea puerto/token al iniciar.
- [x] El `.env` solo se carga en desarrollo; nunca se incluye como requisito del usuario final.
- [x] Tailwind compila utilidades y existe selector de tema claro/oscuro con preferencia en localStorage.
- [ ] Verificar cierre ordenado, arranque fallido y ausencia de backend en pruebas de integración.
- [ ] Probar CSP y flujo de apertura externa desde la app empaquetada.

## Configuración de entorno

Variables opcionales: `SOM_DATA_DIR`, `SOM_BACKUP_DIR`, `SOM_PYTHON`. No añadir claves, contraseñas ni tokens. El token del canal local se genera en Electron y no se configura manualmente.


## Integración externa Sophos

- `SOM-010-08`: La barra lateral ofrece acceso a Sophos Central Policies mediante el navegador del sistema y una URL constante en el proceso principal. SOM no captura ni almacena credenciales o MFA.
- Estado: Implementado como acceso externo; integración de políticas vía API no configurada.

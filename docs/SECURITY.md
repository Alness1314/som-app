# Seguridad

- El backend solo enlaza loopback; las rutas privadas requieren secreto aleatorio de proceso transportado por IPC/preload.
- Chromium usa `contextIsolation`, `nodeIntegration: false`, sandbox y CSP restrictiva. Se bloquea navegación interna no autorizada; solo se delegan destinos HTTPS externos.
- Las llamadas HTTPS verifican certificados por defecto. Una excepción de TLS se presenta como error; no se desactiva la verificación.
- No se guardan credenciales Hillstone. No se automatiza login, MFA, cambios de política ni VPN.
- SHA-256 identifica el contenido importado. El ZIP se inspecciona sin extraerlo y se rechazan rutas ascendentes, tamaños excesivos y alta expansión.
- Los archivos originales no se sobrescriben. La importación conserva copia por hash y nombre.

Pendiente para endurecimiento de producción: almacenar una clave por usuario en Credential Manager si se incorporan credenciales, ACL explícitas para los directorios administrados, política de retención/borrado, migración transaccional Alembic, firma del instalador y pruebas de aislamiento en Windows.


## TLS no confiable por dispositivo

La verificación TLS estricta permanece activa de forma predeterminada. Un operador puede habilitar explícitamente `allow_untrusted_tls` en un dispositivo para que la comprobación HTTPS acepte certificados expirados, autofirmados o con nombre de host no coincidente. Esta opción omite la validación completa del certificado para ese destino y puede permitir ataques de intermediario; usar únicamente en redes administrativas controladas mientras se renueva o instala un certificado confiable. SOM persiste la opción por dispositivo, registra cada comprobación en auditoría y presenta el resultado como TLS no confiable. El ajuste solo afecta las comprobaciones HTTPS que ejecuta SOM; abrir la consola en navegador externo mantiene la política TLS del navegador.

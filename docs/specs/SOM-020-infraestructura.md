# SOM-020 — Infraestructura Hillstone

- Estado: Parcial
- Última revisión: 2026-10-15

## Requisitos

- `SOM-020-01`: Iniciar con Hillstone A2700 (FIREWALL), W620S (WAF) e I1870 (BDS); sus URLs se pueden editar.
- `SOM-020-02`: CRUD de activos valida nombre, tipo y URL HTTPS.
- `SOM-020-03`: Verificación HTTPS tiene timeout, latencia, error y resultado TLS persistidos.
- `SOM-020-04`: TLS estricto es el valor predeterminado. La excepción por dispositivo es opt-in, requiere confirmación y siempre se informa como certificado no validado; una respuesta HTTPS no indica por sí sola que la VPN esté conectada.
- `SOM-020-05`: Abrir consola en navegador externo con URL HTTPS.
- `SOM-020-06`: No guardar credenciales VPN o de consola ni automatizar cambios de seguridad.

## Criterios de aceptación

- [x] Se insertan dispositivos iniciales si la base está vacía; altas/edición/baja y verificaciones están disponibles en API.
- [x] UI permite agregar dispositivo, verificar y abrir consola.
- [x] Certificados se validan por defecto; la excepción explícita por dispositivo queda persistida y los resultados se marcan TLS no verificado; UI mantiene la VPN como desconocida.
- [ ] Añadir edición/baja visual e historial filtrable de conectividad.
- [ ] Crear pruebas aisladas para timeout, error TLS, error DNS y respuesta HTTP.

## Límite

TLS estricto valida certificados por defecto. El modo opt-in por dispositivo omite toda validación TLS para dispositivos con certificados expirados o autofirmados; esto permite ataques de intermediario. Se recomienda instalar un certificado confiable y desactivar la excepción después.

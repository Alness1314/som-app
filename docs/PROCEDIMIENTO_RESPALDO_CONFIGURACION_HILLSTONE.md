# Procedimiento manual: respaldo de configuración Hillstone

**Versión:** 1.0  
**Alcance observado:** consola Hillstone A2700  
**Propósito:** crear un respaldo de la configuración del equipo y descargar el archivo para resguardarlo localmente.

## Alcance y limitación

En el video se observa la consola del A2700 en **System → Configuration File Management → Configuration File List**. La grabación no muestra la creación ni la descarga completa de un respaldo. Los pasos de exportación de esta guía se completan con el manual oficial de StoneOS 5.5R10; los nombres pueden variar entre versiones.

Este procedimiento respalda la **configuración del equipo**. No es el respaldo de logs de las últimas 24 horas que se descarga desde Monitor u otra sección de registros. El video no permite identificar ni documentar el flujo de exportación de esos logs.

La grabación solo confirma la pantalla del A2700. Para WAF y BDS, primero comprueba que sus consolas tengan el mismo menú y flujo; no des por hecho que la navegación es idéntica.

## Antes de comenzar

- Conéctate a la VPN o red de administración autorizada.
- Confirma que la pestaña del navegador corresponde al equipo que vas a respaldar.
- Inicia sesión con una cuenta autorizada y completa MFA o CAPTCHA si se solicita. No compartas ni guardes esos códigos.
- Si aparece una advertencia TLS, confirma con el administrador que la dirección es la correcta antes de continuar. Una excepción de certificado permite acceder, pero no valida la identidad del equipo.
- Prepara una carpeta de destino protegida. Los respaldos de configuración pueden contener información sensible de la red.

## Pasos

1. Abre la consola del equipo correcto e inicia sesión.
2. Ve a **System → Configuration File Management → Configuration File List**.
3. Selecciona **Backup Restore** para abrir las opciones de respaldo.
4. En la sección para respaldar la configuración actual, escribe una descripción reconocible, por ejemplo `Respaldo previo a cambio - AAAA-MM-DD`. No incluyas contraseñas ni otros secretos en la descripción.
5. Inicia el respaldo y espera a que finalice. No cierres la sesión durante la operación.
6. Regresa a **Configuration File List** y confirma que apareció una entrada nueva. Revisa su fecha/hora, tamaño, versión de firmware, usuario y origen cuando estén disponibles.
7. Marca la casilla de esa entrada nueva y pulsa **Export**.
8. Guarda el archivo en una carpeta identificada por dispositivo y fecha, por ejemplo `Respaldos Hillstone\A2700\AAAA-MM-DD`. Conserva el nombre y contenido originales del archivo; si necesitas identificarlo mejor, registra el nombre en un manifiesto aparte.
9. Comprueba que el archivo existe, tiene tamaño mayor que cero y corresponde a la fecha del respaldo. No lo abras ni lo edites para “validarlo”.
10. Registra en la bitácora: dispositivo, fecha y hora, nombre del archivo, tamaño, firmware y operador. Si tu procedimiento interno lo permite, calcula y registra un SHA-256 para detectar cambios posteriores.
11. Repite desde el paso 1 para cada dispositivo, verificando el nombre/modelo antes de crear y exportar el respaldo.

## Si algo falla

- **No aparece una entrada nueva:** considera el respaldo incompleto; revisa el resultado de la tarea y vuelve a intentarlo solo cuando la consola indique que es seguro.
- **Exportación sin archivo o archivo vacío:** registra el intento como fallido y no lo reportes como respaldo exitoso.
- **No encuentras Backup Restore o Export:** detente y confirma la versión/modelo con el administrador; no pruebes opciones de restauración para buscar la exportación.
- **Se solicita MFA/CAPTCHA:** complétalo manualmente en la consola. No intentes evitar ese control.
- **No hay conectividad:** verifica VPN y dirección del equipo con el responsable de red; no cambies reglas de firewall como parte de este procedimiento.

## Precauciones

- No uses **Delete**, **Upload**, **Restore** ni opciones de restablecimiento para este procedimiento.
- No sobrescribas respaldos anteriores.
- Restringe el acceso a la carpeta según la política de la organización y conserva los archivos conforme a la retención aprobada.
- No envíes el archivo por correo o mensajería sin autorización.

## Referencias

- Video proporcionado por el operador: muestra la lista de archivos de configuración del A2700; no muestra la exportación terminada.
- Manual oficial: [StoneOS WebUI User Guide X 5.5R10](https://kb.hillstonenet.com/en/wp-content/uploads/2023/01/StoneOS_WebUI_User_Guide_X_5.5R10-1.pdf), sección **Configuration File List / Backup Restore**. En esa versión, el flujo permite iniciar un respaldo y después seleccionar la entrada generada para exportarla.

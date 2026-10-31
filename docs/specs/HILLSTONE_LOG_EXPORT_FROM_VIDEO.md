# Levantamiento: exportación de logs Hillstone observada en video

**Estado:** requisitos operativos aclarados; integración automatizada pendiente de validación.  
**Fuente:** video `2026-10-20 23-31-01.mp4` compartido por el operador.  
**Propósito:** registrar evidencia útil para diseñar el proveedor de exportación de logs de SOM.

## Conclusión

El flujo de exportación parece automatizable con Playwright en un navegador controlado por SOM, porque en el video las operaciones se realizan desde formularios web: elegir una sección de logs, filtrar un periodo, abrir **Export**, completar opciones y descargar el resultado. El operador aclaró los requisitos funcionales: obtener TXT y CSV, no establecer contraseña de cifrado en el A2700, abarcar el día completo en W620S con todas sus páginas, y usar únicamente las últimas 24 horas en BDS. Cuando una consulta no arroje filas, se debe guardar una captura como evidencia en lugar de crear un archivo de logs vacío.

Esto aún no es una automatización lista para producción: faltan selectores validados, confirmar autenticación y comprobar qué formatos admite realmente cada consola. La meta solicitada es producir ambos formatos por categoría y dispositivo; en el video, el diálogo W620S solo muestra CSV y BDS no muestra un diálogo completo. No se debe sintetizar un formato ausente ni presentar una sola descarga como si fueran ambas; se reportará la limitación hasta validar una exportación real.

El operador confirma que el inicio de sesión de A2700, W620S e I1870 no solicita CAPTCHA; CAPTCHA aplica a Sophos, que queda fuera de este flujo. SOM debe usar credenciales guardadas de forma segura para iniciar sesión en una ventana visible. Si Hillstone presenta MFA, vence la sesión o cambia el formulario, la operación debe detenerse para intervención autorizada. Mientras no haya un proveedor validado por modelo y tipo de log, la interfaz debe etiquetar la descarga automática como no implementada o pendiente de configuración.

## Evidencia visible

| Equipo / sección visible | Periodo y datos visibles | Opciones de exportación observadas | Confianza |
| --- | --- | --- | --- |
| A2700, **Monitor → Log → Threat Log** | **Last 24 Hours**; se ve una tabla de amenazas. | Diálogo **Export**, campo **Encrypted Password** y formatos **TXT / CSV**. Requisito confirmado: dejar el campo de contraseña vacío. | Alta para pantalla y formatos; la aclaración del operador define que no se establece contraseña. |
| W620S, **Monitor → Log → Web Security Log → Log** | Periodo **Today**; la tabla muestra 34,541 registros y 691 páginas con 50 por página. Requisito confirmado: exportación diaria del día completo, abarcando todas las páginas del rango de ese día. | Diálogo con nombre de exportación, formato **CSV** y **Page Range** `1–691`. Advierte que solo puede ejecutarse una exportación a la vez y que no se inicie otra hasta terminar la descarga. | Alta para pantalla, rango y aviso. La consola mostrada expone CSV solamente; soporte TXT queda por verificar. |
| I1870 BDS, **Log & Report → Log → Threat Log** | **Last 24 Hours**; se ve una tabla y paginación de 415 páginas con 50 por página. | Se ve la sección y el comando **Export**, pero no un diálogo completo que permita establecer todas sus opciones. | Alta para la sección y el volumen mostrado; baja para el detalle de exportación. |

También se ve que el operador inicia sesión y que se consultan distintas pestañas de dispositivo. El operador aclara que las consolas Hillstone FW, WAF y BDS no presentan CAPTCHA en su acceso; la consola de Sophos sí puede solicitarlo. La grabación no demuestra persistencia de sesión entre reinicios. Cuando el filtro no devuelva registros, el requisito confirmado es capturar la pantalla del dispositivo, categoría y periodo consultados, y registrar esa captura como evidencia de “sin logs”; no debe presentarse como archivo de logs descargado.

## Flujo candidato para SOM

1. El operador elige dispositivo y tipo de log en SOM.
2. SOM abre o enfoca la ventana visible y el perfil aislado de ese equipo. Si hay credenciales guardadas, SOM intenta completar el formulario de acceso; si no, el operador inicia sesión manualmente. Este paso aplica a Hillstone FW/WAF/BDS, no a Sophos.
3. SOM confirma que está en la consola esperada y navega a la sección de logs configurada específicamente para el modelo.
4. SOM aplica el intervalo confirmado según dispositivo: A2700 usa **Last 24 Hours**; W620S cubre el día completo y ajusta el rango de páginas a todos los resultados de ese día; BDS usa solamente **Last 24 Hours**.
5. SOM solicita los dos formatos requeridos, TXT y CSV, por cada categoría. En A2700 deja vacío el campo **Encrypted Password**. Valida en W620S y BDS si la consola soporta ambos formatos; si uno no está disponible, deja el resultado parcial y muestra qué formato falta.
6. SOM inicia una exportación a la vez por consola, espera a que la descarga termine y no pulsa otra exportación mientras el dispositivo procesa la anterior.
7. Si hay filas, SOM verifica cada archivo nuevo, no vacío, con tipo, tamaño y nombre esperados. Si no hay filas, captura el estado vacío con el dispositivo, categoría y periodo visibles y lo registra como evidencia “sin logs”; no genera archivos ficticios ni marca un respaldo de logs como descargado.
8. SOM conserva los originales, calcula SHA-256, asocia dispositivo, categoría, intervalo y hora de importación, y registra éxito solo después de verificar los archivos requeridos o la evidencia de consulta sin filas.
9. Ante una solicitud de MFA, sesión caducada, error de autenticación, exportación fallida, descarga ambigua o cambio de interfaz, SOM pausa o registra el fallo; no informa éxito ni reintenta acciones destructivas.

## Diferencias que requieren configuraciones por dispositivo

- El A2700 muestra selección de formato TXT/CSV y un campo de contraseña de cifrado, que por instrucción del operador debe dejarse vacío. SOM prioriza descargar TXT y crear localmente un CSV equivalente; si la consola no ofrece TXT, usa su CSV.
- El W620S muestra nombre, formato y rango de páginas; la consola limita una exportación activa a la vez. SOM prioriza TXT y crea el CSV localmente cuando ese formato existe; si no, conserva el CSV nativo. Web Security Log usa `Without Attack Content` y su exportación CSV disponible.
- El BDS muestra una navegación y paginación distintas. En el video no se confirma su diálogo de exportación.
- En el explorador se ven archivos del A2700 con nombres como `FW_EVENTLOG_20_10_2026_CSV.zip`, `FW_EVENTLOG_20_10_2026_TXT.zip`, `FW_NETWORKLOG_20_10_2026_CSV.zip`, `FW_NETWORKLOG_20_10_2026_TXT.zip`, `FW_SESSIONLOG_20_10_2026_CSV.zip`, `FW_SESSIONLOG_20_10_2026_TXT.zip`, `FW_THREATLOG_20_10_2026_CSV.zip` y `FW_THREATLOG_20_10_2026_TXT.zip`. Son los nombres visibles en esa fecha; el patrón de producción esperado es `{PREFIJO}_{DD_MM_YYYY}_{CSV|TXT}.zip`.
- En W620S el diálogo muestra el nombre `WAF_WEBEVENTLOG_20_10_2026_CSV`. En el explorador también se ven capturas PNG con prefijos como `WAF_WEBACCESSLOG`, `WAF_NETWORKLOG` y `WAF_NATLOG`; no se deben confundir esas capturas con los archivos exportados. El video no establece una lista completa de categorías ni todos los nombres finales de archivo.
- Convención propuesta para una captura por consulta vacía: `{DISPOSITIVO}_{CATEGORIA}_{DD_MM_YYYY}_SIN_LOGS.png`. Debe configurarse como evidencia y distinguirse de archivos TXT/CSV. Los nombres definitivos de categorías WAF/BDS necesitan confirmación por consola.

Por ello, SOM necesita perfiles de exportación explícitos por **modelo + categoría de log**, no una secuencia única compartida entre A2700, W620S e I1870.

## Información necesaria antes de automatizar en producción

- Modelo exacto y versión de firmware de cada equipo.
- Categorías de log que deben exportarse por equipo y prioridad de cada una. Los nombres exactos se ven parcialmente para A2700 y W620S; BDS necesita confirmación.
- Definición del intervalo diario y zona horaria de W620S; comprobar cómo convierte “Today” la consola y cómo se determinan todas las páginas si llegan nuevos registros durante la exportación.
- Confirmar que dejar vacío **Encrypted Password** en A2700 produce exportaciones válidas y descargables.
- W620S puede ofrecer formatos distintos según categoría. Preferir el TXT y convertir localmente a CSV; cuando no haya TXT, descargar el CSV nativo. BDS sigue pendiente de confirmación y no está incluido.
- Confirmar nombres/extensiones finales y si los ZIP contienen TXT/CSV UTF-8 con encabezados. Los nombres A2700 vistos siguen la plantilla `FW_{EVENTLOG|NETWORKLOG|SESSIONLOG|THREATLOG}_{DD_MM_YYYY}_{CSV|TXT}.zip`.
- Definir captura “sin logs”: pantalla que debe incluir dispositivo, categoría y periodo, directorio de evidencia y formato de nombre aprobado.
- Cuánto tarda una exportación típica, cómo se indica que terminó y qué pasa si la sesión caduca.
- Confirmación del procedimiento de autenticación autorizado y de cuándo interviene el operador.
- Una ejecución de prueba por modelo y categoría, usando datos aprobados y confirmando que los archivos descargados cubren el intervalo correcto.

No se deben codificar selectores ni llamar endpoints internos observados en DevTools hasta validarlos con autorización y una prueba reproducible. Los endpoints de login/captcha y los campos de autenticación no son parte de este levantamiento.

## Riesgo de exposición en la grabación

En una parte del video queda visible un documento con información que parece incluir datos de acceso. Este documento no transcribe esos datos. Si corresponden a credenciales reales, deben considerarse expuestas y rotarse o revocarse conforme al proceso interno. Evita volver a compartir la grabación sin recortar o difuminar esa sección. Para SOM, usar el almacén seguro de credenciales de Windows; `.env` no debe usarse como almacén de contraseñas en una instalación de escritorio.

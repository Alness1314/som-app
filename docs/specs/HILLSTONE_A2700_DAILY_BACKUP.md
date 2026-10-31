# Alcance inicial de automatización: Hillstone A2700

## Incluido en el primer flujo

El primer proveedor automatizado será únicamente el firewall A2700. Las siete vistas de **Monitor → Log** solicitadas son:

| Vista de consola | Categoría para el nombre |
| --- | --- |
| Event Log | `EVENTLOG` |
| Network Log | `NETWORKLOG` |
| Configuration Log | `CONFIGURATIONLOG` |
| Threat Log | `THREATLOG` |
| Session Log | `SESSIONLOG` |
| NAT Log | `NATLOG` |
| URL Log | `URLLOG` |

Para cada categoría se solicitarán TXT y CSV con intervalo **Last 24 Hours**, sin contraseña de cifrado. El nombre base seguirá `FW_<CATEGORIA>_<DD_MM_YYYY>`; el sufijo de formato y la extensión original que entregue la consola se conservan. No se cambia el nombre dentro del archivo original.

Si la consulta confirma que no hay filas, se guarda una captura PNG como evidencia con nombre `FW_<CATEGORIA>_<DD_MM_YYYY>_SIN_LOGS.png`; esto no se registra como exportación de logs.

Al terminar correctamente, SOM reunirá los archivos exportados y las capturas de esa ejecución en `FW_LOGS_<DD_MM_YYYY>.zip` en el destino elegido. El ZIP contendrá los originales sin modificación y un manifiesto con categoría, formato, nombre, tamaño y SHA-256. No se declarará completa una categoría si faltó uno de los formatos requeridos o la evidencia de consulta vacía.

## Destino de almacenamiento

En **Configuración** se puede elegir carpeta local, ruta compartida NAS disponible para la sesión de Windows o carpeta local sincronizada por el cliente oficial de OneDrive/Google Drive. SOM prueba escritura al guardar la configuración. Las integraciones directas con APIs de nube/OAuth no están incluidas; SOM no guarda tokens de Google/Microsoft.

## Estado y validación requerida

SOM ya ofrece **Iniciar respaldo A2700** desde Respaldos. El flujo automatiza la ventana visible: navega las siete categorías, verifica que el periodo mostrado sea Last 24 Hours, ejecuta Filter, distingue tabla con registros de consulta vacía, pide TXT y CSV uno por uno (contraseña de cifrado en blanco), espera un ZIP descargado y crea el paquete final. Si no puede reconocer la vista o el diálogo, se detiene y no registra la ejecución como exitosa. Los destinos local, NAS y carpeta sincronizada se configuran en Configuración.

La captura recibida documenta Event Log y el diálogo de exportación. La primera verificación integrada usa controles visibles y el resto de categorías reutiliza ese diálogo; debe validarse en una sesión autorizada antes de confiar en una corrida diaria completa. Ante una pantalla vacía no reconocida, el flujo se detiene sin inventar que no hay logs. Las pruebas disponibles usan solo archivos sintéticos; no se ha ejecutado contra el firewall real desde el entorno de desarrollo.

La integración con el Programador de tareas de Windows todavía no está implementada; por ahora el operador inicia la tarea desde el botón. El video y capturas pueden seguir ocultando credenciales, cookies y datos reales.

La automatización debe usar la ventana visible y perfil aislado que ya administra SOM. Si Hillstone muestra un desafío adicional o expira la sesión, se pausa para intervención del operador. No se omiten controles de autenticación.

# Integraciones

## Hillstone

Las direcciones iniciales se registran como configuración editable y se consulta HTTPS con timeout de 8 segundos y validación TLS estándar. Una respuesta web no verifica una VPN; SOM conserva VPN como desconocida.

`HillstoneBackupProvider` define las operaciones de conexión, autenticación, navegación, intervalo y descarga. El proveedor actual está expresamente sin configurar. Para habilitarlo se requiere validar modelos/UI exactos, flujo de exportación, formato resultante y MFA interactivo con autorización. No se inventan selectores CSS ni endpoints.

La primera fase de respaldos importa archivos descargados por una persona. El módulo detecta CSV, JSON, TXT, LOG, XLSX y ZIP por extensión/estructura básica, calcula SHA-256, guarda originales, identifica duplicados y exporta manifiesto. Los formatos desconocidos se conservan y no se interpretan.

Sophos Central, solicitudes, incidentes, TISAX y tareas de Windows son extensiones futuras; no hay conexiones simuladas.

## Sophos Central

SOM incluye un acceso directo externo a **Sophos Central > Endpoint > Policies**: `https://fusion.sophos.com/manage/endpoint/policies/list`. Se abre en el navegador predeterminado y utiliza la sesión autenticada del usuario. SOM no almacena la contraseña, los códigos MFA ni las cookies de Sophos. El vínculo no automatiza ni cambia políticas.

Para Control de periféricos, Sophos documenta la configuración en **Mis productos > Endpoint > Políticas**. Selecciona o crea una política de Control de periféricos y revisa sus asignaciones antes de guardar; la política debe estar activa para aplicar los ajustes.

MFA es un requisito de inicio de sesión de Sophos Fusion. El enlace a políticas no lo controla. El administrador puede gestionar métodos desde el perfil (icono de usuario > **My info / Mi información > Manage MFA / Gestionar MFA**). **Reset MFA** sirve para recuperar o volver a inscribir el método y exige privilegios de Super Admin; no desactiva MFA. Si el acceso se perdió y no hay otro Super Admin, Sophos indica contactar a soporte.

Referencias oficiales: [Control de periféricos](https://docs.sophos.com/central/Customer/help/es-es/ManageYourProducts/EndpointProtection/ConfigureDeviceControl/index.html), [Configurar políticas](https://docs.sophos.com/central/Customer/help/es-es/GettingStarted/SetPolicies/index.html), [Detalles de cuenta y MFA](https://docs.sophos.com/central/Customer/help/en-us/ManageYourAccount/AccountDetails/index.html), [Restablecer MFA](https://docs.sophos.com/central/customer/help/en-us/ManageYourAccount/ModernAuthentication/ModernAuthReset/index.html).

# Desarrollo

Requiere Windows, Node.js 22 y Python 3.12. Desde PowerShell en la raíz, prepara dependencias y ejecuta Electron:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./scripts/setup.ps1
npm run dev
```

La primera ejecución instala los paquetes Node y Python. Vite escucha exclusivamente en `127.0.0.1:5173`. Electron carga el `.env` de la raíz en modo desarrollo, levanta FastAPI en un puerto local dinámico y lo detiene al cerrar.

Tailwind CSS se procesa mediante PostCSS. En desarrollo, Vite requiere estilos inline para HMR; la regla relajada solo se agrega a la CSP servida por Vite. El build empaquetado conserva `style-src 'self'`.

## Solución de problemas de Python

Si `py -3.12 --version` dice que no hay runtime instalado, ejecuta:

```powershell
py install 3.12
.\scripts\setup.ps1
```

El setup recrea `backend/.venv` con Python 3.12 antes de instalar requirements. Esto evita que un entorno anterior con Python 3.14 intente compilar Pandas desde código fuente. Si `pip` falla, el script se detiene; revisa la primera línea `error:` para identificar la dependencia concreta.

Copia `.env.example` a `.env` (o edita el `.env` local, que ya está ignorado por Git). Puedes dejar todos los valores en blanco: los datos se guardan por defecto en `%APPDATA%\SOM\data`, y los respaldos dentro de esa carpeta. Para usar ubicaciones propias, establece rutas absolutas, por ejemplo `SOM_DATA_DIR=D:\SOM\data` y `SOM_BACKUP_DIR=D:\SOM\backups`. `SOM_PYTHON` es opcional y solo sirve para indicar una ruta alternativa a `python.exe`; normalmente se deja vacío.

No configures tokens ni contraseñas en `.env`. Electron genera el token local automáticamente. En la versión empaquetada se usa la carpeta de datos de usuario de Electron y no se carga `.env`.

React usa `HashRouter` para permitir navegación local empaquetada. No abrir endpoints/docs del backend a la red. Los cambios al esquema deben incluir una revisión Alembic.

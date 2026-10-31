# Empaquetado Windows 11 x64

1. Instala Node.js 22 y Python 3.12 en una máquina de compilación.
2. Ejecuta `scripts/setup.ps1`.
3. Ejecuta `scripts/build.ps1`.
4. Confirma el archivo `release/SecurityOperationsManager-Setup-0.1.0.exe`.
5. Instala y ejecuta en una VM limpia de Windows 11 sin Python/Node.

electron-builder genera NSIS x64. PyInstaller produce un backend de un archivo en `backend/dist`. El binario final requiere validación de firma, arranque y ciclo de cierre en una VM limpia. El Programador de tareas y actualizaciones no están configurados.

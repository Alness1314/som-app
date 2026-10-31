$ErrorActionPreference = 'Stop'
$python = 'backend/.venv/Scripts/python.exe'
if (-not (Test-Path $python)) { throw 'Ejecuta scripts/setup.ps1 primero.' }
Push-Location backend
try { & ./.venv/Scripts/python.exe -m PyInstaller --noconfirm --clean --onefile --name som-backend --collect-all uvicorn --collect-all sqlalchemy --collect-submodules som_api som_api/__main__.py }
finally { Pop-Location }
New-Item -ItemType Directory -Force backend/dist | Out-Null

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
        throw 'No se encontró el lanzador de Python. Instala Python 3.12 y vuelve a ejecutar scripts/setup.ps1.'
    }

    & py -3.12 --version
    if ($LASTEXITCODE -ne 0) {
        throw 'No está instalado Python 3.12. Ejecuta "py install 3.12" y vuelve a ejecutar scripts/setup.ps1.'
    }

    # --clear replaces a previous venv (for example one created with Python 3.14).
    & py -3.12 -m venv --clear backend/.venv
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el entorno virtual de Python 3.12.' }

    & backend/.venv/Scripts/python.exe -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo actualizar pip.' }

    & backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Falló la instalación de dependencias Python. Revisa el primer error de pip.' }

    npm install
    if ($LASTEXITCODE -ne 0) { throw 'Falló npm install.' }
} finally {
    Pop-Location
}

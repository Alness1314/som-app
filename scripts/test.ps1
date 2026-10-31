$ErrorActionPreference = 'Stop'
npm run build
backend/.venv/Scripts/python.exe -m pytest backend/tests -q

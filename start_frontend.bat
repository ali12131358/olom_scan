@echo off
chcp 65001 >nul
cd /d "%~dp0frontend"
echo ============================================
echo   MikroTik Scanner - Frontend (port 5001)
echo ============================================
echo.
echo Make sure backend is already running:
echo   start_backend.bat   OR
echo   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
echo.

if not exist node_modules (
  echo npm install...
  call npm install
)

echo Starting Vite on http://localhost:5001
echo.
call npm run dev
pause

@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   MikroTik Scanner - Backend (port 8001)
echo ============================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] python not found on PATH
  pause
  exit /b 1
)

python -c "import uvicorn" 2>nul
if errorlevel 1 (
  echo Installing requirements...
  python -m pip install -r requirements.txt
)

echo Starting: python main.py
echo Health:   http://127.0.0.1:8001/health
echo.
python main.py
pause

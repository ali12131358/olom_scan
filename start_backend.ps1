# MikroTik Scanner - Backend only
Set-Location $PSScriptRoot
Write-Host "Backend: python main.py  (port 8001)" -ForegroundColor Cyan
try { python -c "import uvicorn" 2>$null } catch {
  Write-Host "Installing requirements..." -ForegroundColor Yellow
  python -m pip install -r requirements.txt
}
python main.py

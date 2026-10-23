# MikroTik Scanner - Frontend only (backend must be on :8001)
Set-Location (Join-Path $PSScriptRoot "frontend")
Write-Host "Frontend Vite http://localhost:5001  (proxy -> 127.0.0.1:8001)" -ForegroundColor Cyan
if (-not (Test-Path "node_modules")) { npm install }
npm run dev

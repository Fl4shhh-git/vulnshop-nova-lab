@echo off
title VulnShop + NOVA Lab
cd /d "%~dp0"
echo.
echo  =============================================
echo   VulnShop + NOVA - Laboratorio Web + IA
echo   Felix Prada Silva - Vigilantium 2026
echo  =============================================
echo.
where node >nul 2>&1 || (echo  Falta Node.js 20+: instalalo desde https://nodejs.org & pause & exit /b 1)
if not exist node_modules (echo  Instalando dependencias... & call npm install --no-audit --no-fund)
if not exist .env echo  AVISO: falta el archivo .env con ANTHROPIC_API_KEY: la tienda funciona, NOVA no.
:: Liberar puerto 3000 si esta ocupado por otro proceso
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":3000 " ^| findstr "LISTENING"') do (
  echo  Puerto 3000 ocupado por PID %%a, cerrando proceso...
  taskkill /PID %%a /F >nul 2>&1
)
timeout /t 2 /nobreak >nul
echo  Iniciando servidor en http://localhost:3000  (Ctrl+C para detener)
echo.
start "" http://localhost:3000/login.html
node server.js
pause

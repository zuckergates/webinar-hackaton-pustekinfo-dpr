@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Webinar Database Security - Jalankan Lab
set "WEBINAR_ROOT=%~dp0"
set "WEBINAR_NO_BROWSER=0"
set "WEBINAR_NO_PAUSE=0"
if /I "%~1"=="--no-browser" set "WEBINAR_NO_BROWSER=1"
if /I "%~2"=="--no-browser" set "WEBINAR_NO_BROWSER=1"
if /I "%~1"=="--no-pause" set "WEBINAR_NO_PAUSE=1"
if /I "%~2"=="--no-pause" set "WEBINAR_NO_PAUSE=1"
echo.
echo DATABASE SECURITY IN PRACTICE - DENDI ZUCKERGATES
echo Menyiapkan lab lokal. Biarkan jendela ini terbuka sampai selesai.
echo Build pertama membutuhkan internet dan dapat memakan beberapa menit.
echo.
if not exist "%WEBINAR_ROOT%lab\lab.ps1" (
  echo [GAGAL] Folder lab tidak ditemukan. Ekstrak seluruh ZIP terlebih dahulu.
  goto failed
)
where docker.exe >nul 2>&1
if errorlevel 1 (
  if exist "%ProgramFiles%\Docker\Docker\resources\bin\docker.exe" (
    set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
  ) else (
    echo [GAGAL] Docker Desktop belum terpasang. Pasang Docker Desktop terlebih dahulu.
    goto failed
  )
)
echo [1/3] Memeriksa Docker...
docker info >nul 2>&1
if not errorlevel 1 goto docker_ready
echo Menyalakan Docker Desktop dan menunggu engine siap...
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $exe=Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'; if(-not (Test-Path -LiteralPath $exe)){throw 'Docker Desktop tidak ditemukan. Buka Docker Desktop secara manual.'}; if(-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)){Start-Process -FilePath $exe -WindowStyle Hidden}"
if errorlevel 1 goto failed
set /a WEBINAR_WAIT=0
:wait_docker
docker info >nul 2>&1
if not errorlevel 1 goto docker_ready
set /a WEBINAR_WAIT+=1
if %WEBINAR_WAIT% GEQ 90 (
  echo [GAGAL] Docker belum siap setelah sekitar 3 menit.
  echo Buka Docker Desktop, pastikan Linux containers aktif, lalu klik file ini lagi.
  goto failed
)
powershell.exe -NoProfile -Command "Start-Sleep -Seconds 2"
goto wait_docker
:docker_ready
docker compose version >nul 2>&1
if errorlevel 1 (
  echo [GAGAL] Docker Compose v2 tidak tersedia. Periksa instalasi Docker Desktop.
  goto failed
)
echo.
echo [2/3] Build, setup, dan menyalakan tiga checkpoint...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; try { & (Join-Path $env:WEBINAR_ROOT 'lab\lab.ps1') -Action Start; exit 0 } catch { Write-Host ('[GAGAL] ' + $_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 goto failed
echo.
echo [3/3] Lab siap.
if "%WEBINAR_NO_BROWSER%"=="1" goto success
start "" "http://localhost:8081"
start "" "http://localhost:8082"
start "" "http://localhost:8083"
:success
echo.
echo Vulnerable : http://localhost:8081
echo Query-fixed: http://localhost:8082
echo Hardened   : http://localhost:8083
echo.
echo Login Alice: alice / Lab-A-2026!
echo Login Bob  : bob   / Lab-B-2026!
echo.
echo Menutup jendela ini tidak menghentikan lab.
echo Untuk berhenti: buka PowerShell di folder lab, jalankan .\lab.ps1 Stop
echo Panduan lima simulasi: lab\simulasi-serangan.md
echo.
if "%WEBINAR_NO_PAUSE%"=="0" pause
exit /b 0
:failed
echo.
echo Lab belum berhasil dinyalakan. Periksa pesan di atas, lalu coba lagi.
if "%WEBINAR_NO_PAUSE%"=="0" pause
exit /b 1


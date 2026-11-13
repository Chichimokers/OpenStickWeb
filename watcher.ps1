
# ============================================================
# OPENSTICK WEB - AUTO WATCHER
# Windows -> Debian ARM64 mediante ADB
# Compilacion Go + despliegue + systemd + vigilancia
# ============================================================

param(
    [string]$Project = "D:\Proyectos\OpenStickWeb",
    [string]$Serial = "",
    [string]$Remote = "/opt/openstick-web",
    [int]$PollSeconds = 1
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURACION
# ============================================================

if (-not (Test-Path -LiteralPath $Project -PathType Container)) {
    throw "No existe el proyecto: $Project"
}

$Project = (Resolve-Path -LiteralPath $Project).Path.TrimEnd([char[]]@('\', '/'))

if ($Remote -notmatch '^/[a-zA-Z0-9/_-]+$') {
    throw "Ruta remota no valida: $Remote"
}

if ($PollSeconds -lt 1) {
    throw "PollSeconds debe ser como minimo 1."
}

$GoOutput = Join-Path $Project "bin\server-linux-arm64"
$ServiceFile = Join-Path $Project "openstick-web.service"

$RemoteStage = "/data/local/tmp/openstick-web-deploy"
$RemoteRootScript = "/data/local/tmp/openstick-web-root-command.sh"
$LocalRootScript = Join-Path $Project "bin\root-command.sh"

$ServiceName = "openstick-web"
$ServicePath = "/etc/systemd/system/$ServiceName.service"

# ============================================================
# SYSTEMD UNIT
# ============================================================

$ServiceContent = @"
[Unit]
Description=OpenStick Go Web Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$Remote
ExecStart=$Remote/server
Restart=always
RestartSec=3
KillSignal=SIGTERM
TimeoutStopSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"@

# ============================================================
# LOGS
# ============================================================

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [ERROR] $Message" -ForegroundColor Red
}

# ============================================================
# ESCRIBIR ARCHIVOS LINUX SIN BOM Y CON LF
# ============================================================

function Write-LinuxFile {
    param(
        [string]$Path,
        [string]$Content
    )

    $Normalized = $Content -replace "`r`n", "`n"
    $Normalized = $Normalized -replace "`r", "`n"

    [System.IO.File]::WriteAllText(
        $Path,
        $Normalized,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

# ============================================================
# ADB
# ============================================================

function Invoke-Adb {
    param([string[]]$Arguments)

    & adb @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "Error ejecutando ADB. Codigo: $LASTEXITCODE"
    }
}

# ============================================================
# EJECUTAR SCRIPT REMOTO COMO ROOT
# ============================================================

function Invoke-AdbRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    & adb -s $script:DeviceSerial shell mkdir -p /data/local/tmp

    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo preparar el directorio temporal remoto."
    }

    Write-LinuxFile -Path $script:LocalRootScript -Content $Command

    & adb -s $script:DeviceSerial push `
        $script:LocalRootScript `
        $script:RemoteRootScript

    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo subir el script remoto."
    }

    $Output = @(
        & adb -s $script:DeviceSerial shell `
            "su -c 'sh $script:RemoteRootScript'" 2>&1
    )

    $ExitCode = $LASTEXITCODE

    foreach ($Line in $Output) {
        Write-Host "$Line"
    }

    if ($ExitCode -ne 0) {
        throw "Error ejecutando script remoto como root. Codigo: $ExitCode"
    }

    return $Output
}

# ============================================================
# DETECTAR DISPOSITIVO
# ============================================================

function Get-AdbDevice {

    $Output = @(& adb devices)

    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo consultar ADB."
    }

    $Devices = @(
        $Output |
        Select-Object -Skip 1 |
        Where-Object { $_ -match '^\S+\s+device$' }
    )

    if ($Serial) {

        $Found = @(
            $Devices | Where-Object {
                ($_ -split '\s+')[0] -eq $Serial
            }
        )

        if ($Found.Count -eq 0) {
            throw "No se encuentra el dispositivo ADB: $Serial"
        }

        return $Serial
    }

    if ($Devices.Count -eq 0) {
        throw "No hay dispositivos conectados y autorizados por ADB."
    }

    if ($Devices.Count -gt 1) {
        throw "Hay varios dispositivos. Especifica -Serial."
    }

    return (($Devices[0] -split '\s+')[0])
}

# ============================================================
# VERIFICAR ROOT
# ============================================================

function Test-Root {

    $Output = @(
        & adb -s $script:DeviceSerial shell "su -c 'id -u'" 2>&1
    )

    if (
        $LASTEXITCODE -eq 0 -and
        (($Output -join "").Trim() -eq "0")
    ) {
        return $true
    }

    $Output = @(
        & adb -s $script:DeviceSerial shell id -u 2>&1
    )

    return (
        $LASTEXITCODE -eq 0 -and
        (($Output -join "").Trim() -eq "0")
    )
}

# ============================================================
# COMPROBAR SYSTEMD
# ============================================================

function Test-RemoteSystemd {

    Write-Info "Comprobando systemd..."

    $Command = @'
set -e

if [ -d /run/systemd/system ] && [ -x /usr/bin/systemctl ]; then
    echo SYSTEMD_OK
else
    echo SYSTEMD_UNAVAILABLE
    exit 2
fi
'@

    $Result = @(Invoke-AdbRoot $Command)
    $Status = $Result -join "`n"

    if ($Status -notmatch '(?m)^SYSTEMD_OK\r?$') {
        throw "systemd no esta disponible."
    }

    Write-OK "systemd operativo. Estado degraded permitido."
}

# ============================================================
# INSTALAR O VERIFICAR SERVICIO
# ============================================================

function Install-ServiceIfMissing {

    Write-Info "Comprobando servicio systemd..."

    Test-RemoteSystemd

    $CheckCommand = @"
set -e

if [ -f '$ServicePath' ]; then
    echo SERVICE_EXISTS
else
    echo SERVICE_MISSING
fi
"@

    $Result = @(Invoke-AdbRoot $CheckCommand)
    $Status = $Result -join "`n"

    if ($Status -match '(?m)^SERVICE_EXISTS\r?$') {

        Write-OK "El archivo del servicio ya existe. Se conserva su configuracion."

        $EnableCommand = @"
set -e
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable '$ServiceName.service'
echo SERVICE_ENABLED
"@

        $EnableResult = @(Invoke-AdbRoot $EnableCommand)

        if (($EnableResult -join "`n") -notmatch '(?m)^SERVICE_ENABLED\r?$') {
            throw "No se pudo habilitar el servicio."
        }

        Write-OK "Servicio existente habilitado."
        return
    }

    if ($Status -notmatch '(?m)^SERVICE_MISSING\r?$') {
        throw "No se pudo determinar si existe el servicio: $Status"
    }

    Write-Warn "Instalando servicio..."

    Write-LinuxFile -Path $ServiceFile -Content $ServiceContent

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "shell", "mkdir", "-p", $RemoteStage
    )

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "push", $ServiceFile,
        "$RemoteStage/openstick-web.service"
    )

    $InstallCommand = @"
set -e

mkdir -p /etc/systemd/system

cp '$RemoteStage/openstick-web.service' '$ServicePath'
chmod 644 '$ServicePath'

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable '$ServiceName.service'

echo SERVICE_INSTALLED
"@

    $InstallResult = @(Invoke-AdbRoot $InstallCommand)

    if (($InstallResult -join "`n") -notmatch '(?m)^SERVICE_INSTALLED\r?$') {
        throw "No se pudo confirmar la instalacion del servicio."
    }

    Write-OK "Servicio instalado y habilitado."
}

# ============================================================
# SNAPSHOT DE ARCHIVOS
# ============================================================

function Get-ProjectSnapshot {

    $Files = @(
        Get-ChildItem -LiteralPath $Project -File -Recurse |
        Where-Object {

            $_.FullName -notmatch '(?i)[\\/](bin|data|certs|\.git)[\\/]' -and

            $_.Name -notin @(
                "watcher.ps1",
                "Watch-OpenStick.ps1",
                "openstick-web.service",
                "root-command.sh"
            )
        } |
        Sort-Object FullName
    )

    $Builder = New-Object System.Text.StringBuilder

    foreach ($File in $Files) {

        $Relative = $File.FullName.Substring($Project.Length).
            TrimStart([char[]]@('\', '/'))

        $Hash = (
            Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256
        ).Hash

        [void]$Builder.AppendLine("$Relative|$Hash")
    }

    return $Builder.ToString()
}

# ============================================================
# COMPILAR GO
# ============================================================

function Compile-Backend {

    Write-Info "Compilando Go para Linux ARM64..."

    $OldGOOS = $env:GOOS
    $OldGOARCH = $env:GOARCH
    $OldCGO = $env:CGO_ENABLED

    try {

        $env:GOOS = "linux"
        $env:GOARCH = "arm64"
        $env:CGO_ENABLED = "0"

        Push-Location $Project

        try {

            & go build -trimpath -ldflags "-s -w" -o $GoOutput .

            if ($LASTEXITCODE -ne 0) {
                throw "Error compilando el backend Go."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {

        $env:GOOS = $OldGOOS
        $env:GOARCH = $OldGOARCH
        $env:CGO_ENABLED = $OldCGO
    }

    if (-not (Test-Path -LiteralPath $GoOutput -PathType Leaf)) {
        throw "No se genero el ejecutable ARM64."
    }

    Write-OK "Compilacion terminada."
}

# ============================================================
# DESPLEGAR PROYECTO
# ============================================================

function Deploy-Project {

    Write-Info "Validando archivos del proyecto..."

    foreach ($File in @(
        "main.go",
        "go.mod",
        "index.html",
        "info.html"
    )) {

        $Path = Join-Path $Project $File

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Falta el archivo obligatorio: $Path"
        }
    }

    if (-not (Test-Path (Join-Path $Project "assets") -PathType Container)) {
        throw "No existe la carpeta assets."
    }

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "shell", "mkdir", "-p", $RemoteStage
    )

    Install-ServiceIfMissing

    Compile-Backend

    # --------------------------------------------------------
    # SUBIR ARCHIVOS A STAGING
    # --------------------------------------------------------

    Write-Info "Subiendo ejecutable..."

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "push", $GoOutput,
        "$RemoteStage/server"
    )

    Write-Info "Subiendo HTML..."

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "push",
        (Join-Path $Project "index.html"),
        "$RemoteStage/index.html"
    )

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "push",
        (Join-Path $Project "info.html"),
        "$RemoteStage/info.html"
    )

    Write-Info "Subiendo assets..."

    Invoke-Adb -Arguments @(
        "-s", $script:DeviceSerial,
        "push",
        (Join-Path $Project "assets"),
        "$RemoteStage/"
    )

    # --------------------------------------------------------
    # DESPLIEGUE ATOMICO
    # --------------------------------------------------------

    $DeployCommand = @"
set -e

# Directorios persistentes.
mkdir -p '$Remote/data'
mkdir -p '$Remote/certs'

# Preparar el ejecutable nuevo con otro nombre.
# Nunca sobrescribir directamente el binario en ejecucion.
cp '$RemoteStage/server' '$Remote/server.new'
chmod 755 '$Remote/server.new'

# Preparar HTML temporal.
cp '$RemoteStage/index.html' '$Remote/index.html.new'
cp '$RemoteStage/info.html' '$Remote/info.html.new'

chmod 644 '$Remote/index.html.new'
chmod 644 '$Remote/info.html.new'

# Sustituir HTML.
mv -f '$Remote/index.html.new' '$Remote/index.html'
mv -f '$Remote/info.html.new' '$Remote/info.html'

# Preparar carpeta de assets.
rm -rf '$Remote/assets.new'
cp -a '$RemoteStage/assets' '$Remote/assets.new'
chmod -R 755 '$Remote/assets.new'

# Sustituir assets.
rm -rf '$Remote/assets'
mv '$Remote/assets.new' '$Remote/assets'

# Sustitucion atomica del ejecutable.
mv -f '$Remote/server.new' '$Remote/server'

# Recargar systemd.
/usr/bin/systemctl daemon-reload

# Habilitar inicio automatico.
/usr/bin/systemctl enable '$ServiceName.service'

# Reiniciar servidor.
if ! /usr/bin/systemctl restart '$ServiceName.service'; then
    echo DEPLOY_FAILED
    /usr/bin/journalctl -u '$ServiceName.service' -n 40 --no-pager
    exit 12
fi

sleep 2

# Confirmar que esta activo.
if /usr/bin/systemctl is-active --quiet '$ServiceName.service'; then
    echo DEPLOY_SUCCESS
    /usr/bin/systemctl is-active '$ServiceName.service'
else
    echo DEPLOY_FAILED
    /usr/bin/journalctl -u '$ServiceName.service' -n 40 --no-pager
    exit 13
fi
"@

    Write-Info "Desplegando archivos y reiniciando servicio..."

    $DeployResult = @(Invoke-AdbRoot $DeployCommand)
    $DeployOutput = $DeployResult -join "`n"

    if ($DeployOutput -notmatch '(?m)^DEPLOY_SUCCESS\r?$') {
        throw "El despliegue no confirmo que el servicio este activo."
    }

    Write-OK "Despliegue terminado. Servicio activo."

    Write-Host ""
    Write-Host "HTTP:  http://IP_DEL_STICK/" -ForegroundColor White
    Write-Host "HTTPS: https://IP_DEL_STICK/" -ForegroundColor White
    Write-Host "INFO:  http://IP_DEL_STICK/info" -ForegroundColor White
    Write-Host "API:   http://IP_DEL_STICK/pedido/" -ForegroundColor White
    Write-Host ""
}

# ============================================================
# INICIALIZACION
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "       OPENSTICK WEB - AUTO WATCHER" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go no esta instalado o no esta en PATH."
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "ADB no esta instalado o no esta en PATH."
}

New-Item -ItemType Directory -Path (Join-Path $Project "bin") -Force |
    Out-Null

# Dispositivo.
Write-Info "Buscando OpenStick..."

$script:DeviceSerial = Get-AdbDevice

Write-OK "Dispositivo: $script:DeviceSerial"

# Arquitectura.
$Architecture = (
    & adb -s $script:DeviceSerial shell uname -m 2>&1 |
    Out-String
).Trim()

if ($LASTEXITCODE -ne 0) {
    throw "No se pudo consultar la arquitectura."
}

if ($Architecture -ne "aarch64") {
    throw "Arquitectura incorrecta: $Architecture. Se necesita aarch64."
}

Write-OK "Arquitectura ARM64 confirmada."

# Root.
if (-not (Test-Root)) {
    throw "No hay acceso root mediante ADB."
}

Write-OK "Acceso root confirmado."

# Primer despliegue.
Deploy-Project

$LastSnapshot = Get-ProjectSnapshot
$DeployPending = $false

# ============================================================
# WATCHER
# ============================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " WATCHER ACTIVO" -ForegroundColor Green
Write-Host " Proyecto: $Project"
Write-Host " Dispositivo: $script:DeviceSerial"
Write-Host " Servicio: $ServiceName"
Write-Host " Destino: $Remote"
Write-Host " Intervalo: $PollSeconds segundo(s)"
Write-Host " CTRL+C para detener el watcher."
Write-Host " El servidor seguira funcionando al cerrarlo."
Write-Host "============================================" -ForegroundColor Cyan

while ($true) {

    Start-Sleep -Seconds $PollSeconds

    try {

        $CurrentSnapshot = Get-ProjectSnapshot

        if (
            $CurrentSnapshot -ne $LastSnapshot -or
            $DeployPending
        ) {

            Write-Host ""
            Write-Warn "Cambios detectados o despliegue pendiente."

            # Dar tiempo a que termine de guardarse el archivo.
            Start-Sleep -Milliseconds 700

            Deploy-Project

            # Solo confirmar cambios despues de desplegar correctamente.
            $LastSnapshot = Get-ProjectSnapshot
            $DeployPending = $false

            Write-OK "Cambios desplegados correctamente."
        }
    }
    catch {

        Write-ErrorLog $_.Exception.Message

        $DeployPending = $true

        Write-Warn "Se reintentara el despliegue."
        Start-Sleep -Seconds 3
    }
}

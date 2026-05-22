# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering

[CmdletBinding()]
param()

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    $powershellPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $powershellPath)) {
        $powershellPath = "powershell.exe"
    }

    $arguments = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "`"$PSCommandPath`""
    )

    try {
        $process = Start-Process -FilePath $powershellPath -ArgumentList $arguments -Verb RunAs -PassThru -Wait
        exit $process.ExitCode
    } catch {
        Write-Warning "Administrator privileges are required for installation."
        Write-Warning "Re-run this script from an elevated PowerShell or Command Prompt."
        exit 1
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )
    $executable = $Command[0]
    $arguments  = @()
    if ($Command.Count -gt 1) {
        $arguments = $Command[1..($Command.Count - 1)]
    }
    & $executable @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $($Command -join ' ')"
    }
}

function Resolve-PythonCommand {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3")
    }
    throw "Python 3 is required but was not found. Install Python 3 first, then rerun this installer."
}

function Ensure-Pip {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$PythonCommand
    )
    try {
        Invoke-NativeChecked -Command ($PythonCommand + @("-m", "pip", "--version"))
        return
    } catch {
        Write-Warning "pip was not found for the selected Python runtime. Attempting to bootstrap pip with ensurepip."
    }
    Invoke-NativeChecked -Command ($PythonCommand + @("-m", "ensurepip", "--upgrade"))
    Invoke-NativeChecked -Command ($PythonCommand + @("-m", "pip", "--version"))
}

function Add-MachinePathEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Entry
    )
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $parts       = @()
    if ($machinePath) {
        $parts = $machinePath -split ";" | Where-Object { $_ }
    }
    $normalizedEntry = $Entry.TrimEnd("\")
    foreach ($part in $parts) {
        if ($part.TrimEnd("\").Equals($normalizedEntry, [StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }
    $newPath = if ($parts.Count -gt 0) { ($parts + $Entry) -join ";" } else { $Entry }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

if (-not (Test-IsAdministrator)) {
    Write-Host "Requesting Administrator privileges..."
    Restart-Elevated
}

$repoRoot   = Split-Path -Parent $PSCommandPath
$sourceMain = Join-Path $repoRoot "ezfs2fa.py"
$sourceLib  = Join-Path $repoRoot "ezfs2fa_lib"

if (-not (Test-Path -LiteralPath $sourceMain -PathType Leaf)) {
    throw "Missing source file: $sourceMain"
}
if (-not (Test-Path -LiteralPath $sourceLib -PathType Container)) {
    throw "Missing source directory: $sourceLib"
}

$pythonCommand = Resolve-PythonCommand
Invoke-NativeChecked -Command ($pythonCommand + @("--version"))
Ensure-Pip -PythonCommand $pythonCommand
Invoke-NativeChecked -Command ($pythonCommand + @("-m", "pip", "install", "--upgrade", "fido2"))

$programFilesRoot = $env:ProgramFiles
if (-not $programFilesRoot) {
    throw "ProgramFiles environment variable is not set."
}

$programDataRoot = $env:ProgramData
if (-not $programDataRoot) {
    $programDataRoot = "C:\ProgramData"
}

$installRoot = Join-Path $programFilesRoot "eZFS2FA"
$libexecDir  = Join-Path $installRoot "libexec\ezfs2fa"
$libDir      = Join-Path $libexecDir "ezfs2fa_lib"
$binDir      = Join-Path $installRoot "bin"

$mainTarget  = Join-Path $libexecDir "ezfs2fa.py"
$wrapperPath = Join-Path $binDir "ezfs2fa.cmd"

$configDir   = Join-Path $programDataRoot "ezfs2fa"
$configPath  = Join-Path $configDir "ezfs2fa.json"

$null        = New-Item -ItemType Directory -Force -Path $libDir, $binDir, $configDir

Copy-Item -LiteralPath $sourceMain -Destination $mainTarget -Force
Get-ChildItem -LiteralPath $libDir -Filter "*.py" -File -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -LiteralPath $sourceLib -Filter "*.py" -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $libDir $_.Name) -Force
}

$wrapperContent = @"
@echo off
setlocal
python --version >nul 2>&1
if errorlevel 1 (
    py -3 --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python 3 is required.
        exit /b 1
    )
    set "PYTHON=py -3"
) else (
    set "PYTHON=python"
)
if not defined EZFS2FA_CONFIG set "EZFS2FA_CONFIG=$configPath"
%PYTHON% "$mainTarget" -c "%EZFS2FA_CONFIG%" %*
"@
Set-Content -LiteralPath $wrapperPath -Value $wrapperContent -Encoding ASCII

Add-MachinePathEntry -Entry $binDir

if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    Invoke-NativeChecked -Command ($pythonCommand + @($mainTarget, "-c", $configPath, "init"))
}

Write-Host ""
Write-Host "Installed eZFS2FA+ for Windows."
Write-Host "Command:"
Write-Host "    ezfs2fa"
Write-Host ""
Write-Host "Installed files:"
Write-Host "    $installRoot"
Write-Host ""
Write-Host "Config:"
Write-Host "    $configPath"
Write-Host ""
Write-Host "If 'ezfs2fa' is not found in your current shell, open a new terminal window."

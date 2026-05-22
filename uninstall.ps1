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
        Write-Warning "Administrator privileges are required for uninstall."
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
    return $null
}

function Remove-MachinePathEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Entry
    )
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not $machinePath) {
        return
    }
    $normalizedEntry = $Entry.TrimEnd("\")
    $parts           = $machinePath -split ";" | Where-Object { $_ }
    $filtered        = @()

    foreach ($part in $parts) {
        if (-not $part.TrimEnd("\").Equals($normalizedEntry, [StringComparison]::OrdinalIgnoreCase)) {
            $filtered += $part
        }
    }

    $newPath = if ($filtered.Count -gt 0) { $filtered -join ";" } else { "" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

if (-not (Test-IsAdministrator)) {
    Write-Host "Requesting Administrator privileges..."
    Restart-Elevated
}

$programFilesRoot = $env:ProgramFiles
if (-not $programFilesRoot) {
    throw "ProgramFiles environment variable is not set."
}

$programDataRoot = $env:ProgramData
if (-not $programDataRoot) {
    $programDataRoot = "C:\ProgramData"
}

$installRoot   = Join-Path $programFilesRoot "eZFS2FA"
$binDir        = Join-Path $installRoot "bin"
$wrapperPath   = Join-Path $binDir "ezfs2fa.cmd"
$configDir     = Join-Path $programDataRoot "ezfs2fa"
$configPath    = Join-Path $configDir "ezfs2fa.json"
$expectedRoot  = [IO.Path]::GetFullPath((Join-Path $programFilesRoot "eZFS2FA"))
$resolvedRoot  = [IO.Path]::GetFullPath($installRoot)

if (-not $resolvedRoot.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove unexpected install path: $resolvedRoot"
}

if (Test-Path -LiteralPath $wrapperPath -PathType Leaf) {
    Remove-Item -LiteralPath $wrapperPath -Force
}

Remove-MachinePathEntry -Entry $binDir

if (Test-Path -LiteralPath $installRoot -PathType Container) {
    Remove-Item -LiteralPath $installRoot -Recurse -Force
}

if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    Write-Host ""
    Write-Warning "Deleting $configPath can prevent access to your encrypted datasets."
    $confirm = Read-Host "Type Yes (exactly) to confirm deletion of this configuration file"
    if ($confirm -ceq "Yes") {
        Remove-Item -LiteralPath $configPath -Force
        Write-Host "Deleted $configPath"
        if (Test-Path -LiteralPath $configDir -PathType Container) {
            if (-not (Get-ChildItem -LiteralPath $configDir -Force | Select-Object -First 1)) {
                Remove-Item -LiteralPath $configDir -Force
            }
        }
    } else {
        Write-Host "Skipped deleting $configPath"
    }
}

$pythonCommand = Resolve-PythonCommand
if ($pythonCommand) {
    try {
        Invoke-NativeChecked -Command ($pythonCommand + @("-m", "pip", "uninstall", "-y", "fido2"))
    } catch {
        Write-Warning "Could not uninstall Python package 'fido2': $($_.Exception.Message)"
    }
} else {
    Write-Warning "Python was not found. Skipping optional pip uninstall for fido2."
}

Write-Host ""
Write-Host "Uninstall complete."

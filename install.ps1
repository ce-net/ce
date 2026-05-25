#Requires -Version 5.1
# CE Windows Installer
# Usage: irm https://raw.githubusercontent.com/ce-net/ce/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

$Repo = "ce-net/ce"
$BinName = "ce.exe"
$AssetName = "ce-windows-amd64.zip"

Write-Host "Fetching latest CE release..."
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Version = $Release.tag_name
$Asset = $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1

if (-not $Asset) {
    Write-Error "Could not find $AssetName in release $Version. Check: https://github.com/$Repo/releases"
    exit 1
}

Write-Host "Downloading CE $Version..."
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "ce-install-$([System.Guid]::NewGuid())"
New-Item -ItemType Directory -Path $TmpDir | Out-Null

$ZipPath = Join-Path $TmpDir "ce.zip"
Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $ZipPath
Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

$InstallDir = Join-Path $env:USERPROFILE ".local\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

$Dest = Join-Path $InstallDir $BinName
Copy-Item (Join-Path $TmpDir $BinName) $Dest -Force
Remove-Item $TmpDir -Recurse -Force

$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "User")
    $env:PATH += ";$InstallDir"
    Write-Host "Added $InstallDir to your PATH."
}

Write-Host ""
Write-Host "CE $Version installed to $Dest"
Write-Host ""
Write-Host "Quick start:"
Write-Host "  ce start    # join the mesh (finds LAN peers automatically)"
Write-Host "  ce status   # check node ID, height, balance"
Write-Host "  ce id       # print your node ID"
Write-Host ""
Write-Host "Source: https://github.com/$Repo"

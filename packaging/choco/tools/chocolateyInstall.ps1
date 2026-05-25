$ErrorActionPreference = 'Stop'

$packageArgs = @{
    packageName    = $env:ChocolateyPackageName
    fileType       = 'zip'
    url64bit       = 'https://github.com/ce-net/ce/releases/download/v0.1.0/ce-windows-amd64.zip'
    checksum64     = 'PLACEHOLDER'
    checksumType64 = 'sha256'
    unzipLocation  = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
}

Install-ChocolateyZipPackage @packageArgs

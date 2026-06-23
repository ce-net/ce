$ErrorActionPreference = 'Stop'

$packageArgs = @{
    packageName    = $env:ChocolateyPackageName
    fileType       = 'zip'
    url64bit       = 'https://github.com/ce-net/ce/releases/download/v0.1.0/ce-windows-amd64.zip'
    checksum64     = '8b2064e46ffacca054d51c4f312eb9e5c89104fdec6d35c3199fc2474a6b42a3'
    checksumType64 = 'sha256'
    unzipLocation  = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
}

Install-ChocolateyZipPackage @packageArgs

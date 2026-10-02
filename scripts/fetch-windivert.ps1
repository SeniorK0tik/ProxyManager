# Downloads WinDivert (x64 DLL + signed driver) into the given directory.
param(
    [string]$Version = "2.2.2",
    [string]$Dest = "vendor/windivert"
)
$ErrorActionPreference = "Stop"

$name = "WinDivert-$Version-A"
$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/$name.zip"
$zip = Join-Path ([System.IO.Path]::GetTempPath()) "$name.zip"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "$name-extract"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $tmp -Force

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$tmp/$name/x64/WinDivert.dll", "$tmp/$name/x64/WinDivert64.sys" $Dest -Force
Copy-Item "$tmp/$name/LICENSE" (Join-Path $Dest "WinDivert-LICENSE.txt") -Force -ErrorAction SilentlyContinue

Get-FileHash (Join-Path $Dest "WinDivert*") -Algorithm SHA256 | Format-Table -AutoSize

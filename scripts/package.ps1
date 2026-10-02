# Builds dist/ProxyManager-windows-x64.zip from a release build and the WinDivert files.
param([string]$WinDivert = "vendor/windivert")
$ErrorActionPreference = "Stop"

$out = "dist/ProxyManager"
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null

Copy-Item target/release/proxy-manager.exe $out
Copy-Item (Join-Path $WinDivert "*") $out
Copy-Item README.md, config.example.toml $out

Compress-Archive -Path "$out/*" -DestinationPath dist/ProxyManager-windows-x64.zip -Force
Get-ChildItem dist/ProxyManager-windows-x64.zip

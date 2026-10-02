# Builds the distribution zip (and its SHA-256 file) from a release build and the WinDivert files.
#   ./scripts/package.ps1                    -> dist/ProxyManager-windows-x64.zip
#   ./scripts/package.ps1 -Version v0.1.0    -> dist/ProxyManager-v0.1.0-windows-x64.zip
param(
    [string]$WinDivert = "vendor/windivert",
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"

$suffix = if ($Version) { "-$Version" } else { "" }
$zip = "dist/ProxyManager$suffix-windows-x64.zip"
$out = "dist/ProxyManager"
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null

Copy-Item target/release/proxy-manager.exe $out
Copy-Item (Join-Path $WinDivert "*") $out
Copy-Item README.md, CHANGELOG.md, config.example.toml $out

Compress-Archive -Path "$out/*" -DestinationPath $zip -Force
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
"$hash  $(Split-Path $zip -Leaf)" | Out-File -Encoding ascii -NoNewline "$zip.sha256"
Get-ChildItem dist -File | Format-Table Name, Length -AutoSize

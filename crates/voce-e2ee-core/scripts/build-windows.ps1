# Build voce-e2ee-core for Flutter FFI (Windows MSVC).
# Usage (from repo root or any cwd):
#   powershell -File crates/voce-e2ee-core/scripts/build-windows.ps1

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $Vcvars)) {
  $Vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $Vcvars)) {
  throw "VS2022 vcvars64.bat not found"
}

$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$env:Path = "$CargoBin;$env:Path"
$env:RUSTUP_DIST_SERVER = "https://rsproxy.cn"
$env:RUSTUP_UPDATE_ROOT = "https://rsproxy.cn/rustup"

cmd /c "`"$Vcvars`" >nul && set Path=$CargoBin;%Path% && cd /d `"$Root`" && cargo build -p voce-e2ee-core --release"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Dll = Join-Path $Root "target\release\voce_e2ee_core.dll"
Write-Host "Built: $Dll"
Get-Item $Dll | Format-List Name, Length, LastWriteTime

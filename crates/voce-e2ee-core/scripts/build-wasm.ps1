# Build voce-e2ee-core for the browser (Windows / Cargo 1.97+).
# wasm-pack's --out-dir is incompatible with Cargo 1.97; use cargo + wasm-bindgen.
$ErrorActionPreference = "Stop"
$Crate = Resolve-Path (Join-Path $PSScriptRoot "..")
$Root = Resolve-Path (Join-Path $Crate "..\..")
$Pkg = Join-Path $Crate "pkg"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
$env:RUSTUP_DIST_SERVER = "https://rsproxy.cn"
$env:RUSTUP_UPDATE_ROOT = "https://rsproxy.cn/rustup"

rustup target add wasm32-unknown-unknown | Out-Null
if (-not (Get-Command wasm-bindgen -ErrorAction SilentlyContinue)) {
  cargo install wasm-bindgen-cli --locked
}

$Vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$Vcvars`" >nul && set Path=$env:USERPROFILE\.cargo\bin;%Path% && cd /d `"$Root`" && cargo build -p voce-e2ee-core --target wasm32-unknown-unknown --features wasm --release"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $Pkg | Out-Null
$Wasm = Join-Path $Root "target\wasm32-unknown-unknown\release\voce_e2ee_core.wasm"
wasm-bindgen $Wasm --out-dir $Pkg --target web --typescript
Write-Host "WASM package: $Pkg"
Get-ChildItem $Pkg | Format-Table Name, Length

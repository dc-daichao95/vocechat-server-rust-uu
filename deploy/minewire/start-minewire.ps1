# Start / verify Minewire sidecar under WSL from Windows PowerShell.
# Usage:
#   .\start-minewire.ps1
#   .\start-minewire.ps1 -VerifyOnly

param(
  [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$distro = "Ubuntu-22.04"
$mineDir = "/mnt/c/Users/Administrator/repo/vocechat/vocechat-server-rust-uu/deploy/minewire"

function Invoke-WslBash([string]$cmd) {
  & wsl -d $distro -- bash -lc $cmd
}

if (-not $VerifyOnly) {
  # Ensure LF scripts + background start
  Invoke-WslBash @"
cd '$mineDir'
python3 -c \"import pathlib; p=pathlib.Path('start-wsl.sh'); p.write_bytes(p.read_bytes().replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n'))\" 2>/dev/null || true
chmod +x start-wsl.sh verify-listen.sh install-wsl.sh 2>/dev/null || true
bash start-wsl.sh --bg
"@
}

Invoke-WslBash "cd '$mineDir' && bash verify-listen.sh"
Write-Host "Minewire ops package ready. Docs: docs/MINEWIRE_TUNNEL.md"

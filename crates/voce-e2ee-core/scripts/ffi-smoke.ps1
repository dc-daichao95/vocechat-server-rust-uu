# Smoke-test voce_e2ee_core.dll via P/Invoke (Phase B gate).
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Dll = Join-Path $Root "target\release\voce_e2ee_core.dll"
if (-not (Test-Path $Dll)) {
  & (Join-Path $PSScriptRoot "build-windows.ps1")
}
if (-not (Test-Path $Dll)) { throw "DLL missing: $Dll" }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class VoceE2ee {
  [DllImport(@"$($Dll.Replace('\','\\'))", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
  public static extern IntPtr voce_e2ee_call(string method, string jsonArgs);

  [DllImport(@"$($Dll.Replace('\','\\'))", CallingConvention = CallingConvention.Cdecl)]
  public static extern void voce_e2ee_free(IntPtr p);

  public static string Call(string method, string json) {
    IntPtr p = voce_e2ee_call(method, json);
    if (p == IntPtr.Zero) throw new Exception("null return");
    try {
      return Marshal.PtrToStringAnsi(p);
    } finally {
      voce_e2ee_free(p);
    }
  }
}
"@

$out = [VoceE2ee]::Call("version", "{}")
Write-Host "voce_e2ee_call(version) => $out"
if ($out -notmatch '"ok"\s*:\s*true') { throw "unexpected: $out" }
if ($out -notmatch '0\.1\.0') { throw "version missing: $out" }
Write-Host "FFI smoke OK"

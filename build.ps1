# build.ps1 -- build znn-address-generator-cuda on Windows with nvcc + MSVC.
#
# nvcc needs an MSVC host toolchain (cl.exe plus its INCLUDE/LIB environment).
# This script locates a Visual Studio / Build Tools install, imports its
# x64 developer environment, then compiles main.cu.
#
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1 [-Arch sm_86]

param(
    [string]$Arch    = "sm_86",   # RTX 3060 = sm_86; adjust for your GPU
    [string]$Out     = "znn-address-generator-cuda.exe",
    [string]$Version = "1.0.0"    # embedded as --version output; overridden for tagged releases
)

$ErrorActionPreference = "Stop"

function Find-VcVars {
    # Prefer vswhere, fall back to well-known install roots.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($path) {
            $vc = Join-Path $path "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $vc) { return $vc }
        }
    }
    $roots = @(
        "${env:ProgramFiles}\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    )
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $hit = Get-ChildItem -Path $root -Recurse -Filter "vcvars64.bat" -ErrorAction SilentlyContinue |
                   Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    throw "Could not find vcvars64.bat. Install Visual Studio Build Tools with the C++ workload."
}

$vcvars = Find-VcVars
Write-Host "Using MSVC environment: $vcvars"

# Import the developer environment into this session.
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

$nvcc = (Get-Command nvcc -ErrorAction SilentlyContinue)
if (-not $nvcc) { throw "nvcc not found on PATH. Install the CUDA Toolkit." }

Write-Host "Compiling with nvcc (-arch=$Arch, version=$Version) ..."
& nvcc -O3 -std=c++17 "-arch=$Arch" "-DZNN_VERSION=\`"$Version\`"" -o $Out main.cu
if ($LASTEXITCODE -ne 0) { throw "nvcc failed with exit code $LASTEXITCODE" }

Write-Host "Built $Out"

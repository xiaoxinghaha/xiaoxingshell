#Requires -Version 7
# 一键打包脚本：构建 release 并把产物集中到 dist\ 目录。
# 用法：
#   pwsh build.ps1            # 构建并输出 dist\xiaoxingshell.exe
#   pwsh build.ps1 -Desktop   # 构建后同时更新桌面上的 xiaoxingshell.exe 副本
param([switch]$Desktop)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = $PSScriptRoot
Set-Location $root

Write-Host "==> 项目目录: $root"

# 读取 Cargo.toml 中的版本号，用于产物标识
$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"' |
    Select-Object -First 1).Matches[0].Groups[1].Value
$commit = git rev-parse --short HEAD

Write-Host "==> 开始构建 release（版本 $version，commit $commit）..."
cargo build --release --bin xiaoxingshell
if ($LASTEXITCODE -ne 0) { throw "cargo build 失败，退出码 $LASTEXITCODE" }

$src = Join-Path $root 'target\release\xiaoxingshell.exe'
if (-not (Test-Path $src)) { throw "构建产物不存在: $src" }

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$dst = Join-Path $dist 'xiaoxingshell.exe'
Copy-Item $src $dst -Force

$item = Get-Item $dst
Write-Host ""
Write-Host "================ 打包完成 ================"
Write-Host "  产物文件 : $($item.FullName)"
Write-Host "  版本     : $version (commit $commit)"
Write-Host "  大小     : $([math]::Round($item.Length / 1MB, 2)) MB"
Write-Host "  生成时间 : $($item.LastWriteTime)"
Write-Host "=========================================="

if ($Desktop) {
    $desk = Join-Path $env:USERPROFILE 'Desktop\xiaoxingshell.exe'
    Copy-Item $dst $desk -Force
    Write-Host "  已同步到桌面: $desk"
}

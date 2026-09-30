#Requires -Version 7
# 一键打包脚本：构建 release，并把 exe 同步到 release\、dist\ 和桌面三处。
# 用法：
#   pwsh build.ps1              # 构建并输出三处 xiaoxingshell.exe
#   pwsh build.ps1 -SkipDesktop # 只输出到 release\ 和 dist\（桌面目录不可写时用）
param([switch]$SkipDesktop)

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

$item = Get-Item $src
$sizeMb = [math]::Round($item.Length / 1MB, 2)

# 产物落点：release\（发布归档目录）、dist\（本地运行目录）、桌面。
# 桌面路径走 shell API 解析，OneDrive 重定向过的桌面也能拿到真实位置。
$targets = @('release', 'dist')
if (-not $SkipDesktop) { $targets += 'desktop' }

Write-Host ""
Write-Host "==> 同步产物（版本 $version，commit $commit，$sizeMb MB）"
$failed = @()
foreach ($t in $targets) {
    try {
        switch ($t) {
            'release' { $dir = Join-Path $root 'release' }
            'dist'    { $dir = Join-Path $root 'dist' }
            'desktop' { $dir = [Environment]::GetFolderPath('Desktop') }
        }
        if (-not $dir) { throw "目标目录解析为空" }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dst = Join-Path $dir 'xiaoxingshell.exe'
        Copy-Item $src $dst -Force
        Write-Host "  [OK]   $dst"
    } catch {
        $failed += $t
        Write-Host "  [FAIL] $t 复制失败: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "================ 打包完成 ================"
Write-Host "  源产物   : $($item.FullName)"
Write-Host "  版本     : $version (commit $commit)"
Write-Host "  大小     : $sizeMb MB"
Write-Host "  生成时间 : $($item.LastWriteTime)"
Write-Host "=========================================="

# 构建本身已成功，落点失败只提示不抛错；两处仓库内产物都失败才算打包失败。
if ($failed -contains 'release' -or $failed -contains 'dist') {
    throw "产物同步失败: $($failed -join ', ')"
}
if ($failed.Count -gt 0) {
    Write-Host "  注意：未同步 $($failed -join ', ')，其余落点已更新。" -ForegroundColor Yellow
}

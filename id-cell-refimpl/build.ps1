# =============================================================================
# ID-CELL 参考实现 · 构建脚本（Windows / PowerShell）
#
# 编译器链：优先用系统里的 cl / gcc / clang；都没有时回落到 ziglang（pip 包）。
#   python -m ziglang cc -std=c99 -Iinclude ...
#
# 用法：
#   .\build.ps1                # 构建库 + quickstart + selftest
#   .\build.ps1 -Target wasm32-wasi
# =============================================================================
param(
    [string]$Target = "native",
    [string[]]$Defines = @(),
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root "build"
$inc   = Join-Path $root "include"
$srcInc = Join-Path $root "src"

if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }
if (-not (Test-Path $build)) { New-Item -ItemType Directory -Path $build | Out-Null }

# ---------------------------------------------------------------- 编译器探测

function Find-Compiler {
    # 1) ziglang（pip 包，自带 clang + lld）
    $zig = Get-Command python -ErrorAction SilentlyContinue
    if ($zig) {
        $probe = & python -c "import ziglang,os,sys;print(os.path.join(os.path.dirname(ziglang.__file__),'zig.exe'))" 2>$null
        if ($probe -and (Test-Path $probe)) { return @{ kind = "zig"; exe = $probe } }
    }
    # 2) 系统 clang / gcc / cl
    foreach ($c in @("clang", "gcc", "cl")) {
        $g = Get-Command $c -ErrorAction SilentlyContinue
        if ($g) { return @{ kind = "native"; exe = $g.Source } }
    }
    return $null
}

$cc = Find-Compiler
if (-not $cc) {
    Write-Host "[build] 找不到 C 编译器。请安装 clang/gcc/MSVC，或执行：pip install ziglang" -ForegroundColor Red
    exit 1
}

$srcs = Get-ChildItem (Join-Path $root "src") -Filter *.c | Sort-Object Name
$extra = @()

function Invoke-Cc {
    param([string[]]$CArgs)
    # 编译器把 warning 写到 stderr；PowerShell 会把它当成错误记录，
    # 因此这里临时放开 ErrorActionPreference，只按退出码判断成败。
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if ($cc.kind -eq "zig") {
        & $cc.exe cc @CArgs 2>&1 | Out-Host
    } else {
        & $cc.exe @CArgs 2>&1 | Out-Host
    }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0) {
        Write-Host "[build] 命令失败（退出码 $rc）" -ForegroundColor Red
    }
    return $rc
}

# ---------------------------------------------------------------- 编译

$objs = @()
$failed = $false

foreach ($s in $srcs) {
    $obj = Join-Path $build ($s.BaseName + ".o")
    $targs = @("-std=c99", "-Wall", "-Wextra", "-I", $inc, "-I", $srcInc, "-c", $s.FullName, "-o", $obj)
    if ($Target -ne "native") { $targs = @("-target", $Target) + $targs }
    $targs = $targs + $Defines
    $rc = Invoke-Cc $targs
    if ($rc -ne 0) { Write-Host "[build] 编译失败: $($s.Name)" -ForegroundColor Red; $failed = $true; break }
    $global:LASTEXITCODE = 0
    $objs += $obj
}

if ($failed) { exit 1 }
Write-Host "[build] 库对象: $($objs.Count) 个"

# ---------------------------------------------------------------- 可执行文件

$progs = @(
    @{ src = "examples/quickstart.c";     name = "quickstart" },
    @{ src = "tests/selftest.c";         name = "selftest" },
    @{ src = "tests/selftest_wire.c";    name = "selftest-wire" },
    @{ src = "tests/idcell_v11_vectors.c"; name = "idcell-v11-vectors" },
    @{ src = "tests/idcell_contract_vectors.c"; name = "idcell-contract-vectors" },
    @{ src = "tests/idcell_discovery_vectors.c"; name = "idcell-discovery-vectors" },
    @{ src = "tests/idcell_security_vectors.c"; name = "idcell-security-vectors" },
    @{ src = "tools/idcell_cli.c";       name = "idcell-cli" }
)

foreach ($p in $progs) {
    $sp = Join-Path $root $p.src
    if (-not (Test-Path $sp)) { continue }
    $obj = Join-Path $build (($p.src -replace '[\\/]', '_') + ".o")
    $targs = @("-std=c99", "-Wall", "-Wextra", "-I", $inc, "-I", $srcInc, "-c", $sp, "-o", $obj)
    # 黑盒套件要 include tests/ 下的独立线缆探针头（§11.3 的 L2 字节层）
    if ($p.src -like "tests/*") { $targs = @("-I", (Join-Path $root "tests")) + $targs }
    if ($Target -ne "native") { $targs = @("-target", $Target) + $targs }
    $targs = $targs + $Defines
    $rc = Invoke-Cc $targs
    if ($rc -ne 0) { Write-Host "[build] 编译失败: $($p.src)" -ForegroundColor Red; $failed = $true; continue }
    $exe = Join-Path $build ($p.name + $(if ($Target -eq "native") { ".exe" } else { ".wasm" }))
    $largs = @("-o", $exe, $obj) + $objs
    if ($Target -ne "native") { $largs = @("-target", $Target) + $largs }
    # CLI 用 CommandLineToArgvW 取 UTF-8 argv，需要 shell32（POSIX 目标不需要）
    if ($Target -eq "native" -and $p.name -eq "idcell-cli") {
        if ($cc.kind -eq "zig") { $largs += "-lshell32" } else { $largs += "shell32.lib" }
    }
    $rc = Invoke-Cc $largs
    if ($rc -ne 0) { Write-Host "[build] 链接失败: $($p.name)" -ForegroundColor Red; $failed = $true; continue }
    Write-Host "[build] 生成 $($exe)"
}

if ($failed) { exit 1 }
Write-Host "[build] 完成。" -ForegroundColor Green
exit 0

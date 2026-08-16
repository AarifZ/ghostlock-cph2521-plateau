/* OPPO Reno 10 Pro Plus 5G (CPH2521)
 * Build: CPH2521_16.0.5.1002 (EX01B100P01)
 * Kernel: 5.10.236-android12-9-o-g74d132f4467a
 * Source: boot.img kallsyms + ARM64 disassembly of Image
 *
 * CRITICAL (re-verified from real ashmem_fops / configfs_bin_file_operations):
 *  - Kernel is CFI-enabled: fops tables store *.cfi_jt stubs, NOT raw funcs.
 *    Putting raw function VAs in fake fops → CFI reject (errno 22).
 *  - file_operations is Android 5.10 + mmap_supported_flags (open@0x70).
 *  - mm_struct size 0x3c0 (mm_cache_init mov w1,#0x3c0), SLUB order-2 best.
 *  - waiter: stp task,lock [waiter,#0x30]; prio@0x40; deadline@0x48; pi_tree@0x18
 *  - no kmalloc-cg-* strings → KMALLOC_CACHE_TYPES=3
 *  - KIMAGE _text = 0xffffffc008000000; kernel_phys_load via KPHYS= (default 0xa8000000)
 *  - PSELECT_SHIFT=-2 measured on device (shift=0 softboots at overlay;
 *    -2 reaches CFI probe). Build default via -DPSELECT_WAITER_WORD_SHIFT=(-2).
 */

/* Primary uname match (device-reported, no -4k suffix) */
OFFSETS_ENTRY("5.10.236-android12-9-o-g74d132f4467a",
  .kernel_phys_load=0x00000000, /* runtime: KPHYS=0xa8000000 (Qualcomm default) */
  STRUCT_OFFSETS_5_10,
  .off_init_task=0x027CC000, .off_init_cred=0x027E0BE0, .off_init_uts_ns=0x027CBDA8,
  .off_empty_zero_page=0x029C3000, .off_root_task_group=0x029C8040,
  .off_selinux_enforcing=0x02A793C8, .off_kptr_restrict=0x027BCF68,
  .off_selinux_blob_sizes=0x02302940, .off_security_hook_heads=0x023022A8,
  .off_kmalloc_caches=0x02301DE0, .off_anon_pipe_buf_ops=0x0216A7E8,
  /* ashmem_misc + offsetof(miscdevice, fops) = +0x10 */
  .off_ashmem_misc_fops=0x0291A8E8, .off_ashmem_fops=0x022BFDC8,
  /* CFI jump tables — must match values stored in real ashmem_fops */
  .off_ashmem_ioctl=0x01837928, .off_ashmem_compat_ioctl=0x01837930,
  .off_ashmem_mmap=0x01822A68, .off_ashmem_open=0x01831488,
  .off_ashmem_release=0x01831490, .off_ashmem_show_fdinfo=0x01822BE8,
  /* configfs bin r/w + splice/llseek also via CFI JT */
  .off_configfs_read_iter=0x0182FCF8, .off_configfs_bin_write_iter=0x01830218,
  .off_copy_splice_read=0x01822B58, .off_noop_llseek=0x0181FE48,
  .off_ashmem_llseek=0x0181FEF8, .off_ashmem_read_iter=0x01822948,
  .off_bss_tail_lock=0x02BB9D00,
  .off_cap_capable_active=0x00000000,
  .off_slide_nfulnl_logger=0x027C14B8, .off_slide_loggers_0_1=0x027C13F0,
  .off_slide_boot_id=0x02B99B6D,
  .off_system_unbound_wq=0x027B9E88,
  /* work->func is CFI-checked on queue */
  .off_call_usermodehelper_exec_work=0x0183E200,
),

/* Alias if runtime uname appends -4k (some GKI builds do) */
OFFSETS_ENTRY("5.10.236-android12-9-o-g74d132f4467a-4k",
  .kernel_phys_load=0x00000000,
  STRUCT_OFFSETS_5_10,
  .off_init_task=0x027CC000, .off_init_cred=0x027E0BE0, .off_init_uts_ns=0x027CBDA8,
  .off_empty_zero_page=0x029C3000, .off_root_task_group=0x029C8040,
  .off_selinux_enforcing=0x02A793C8, .off_kptr_restrict=0x027BCF68,
  .off_selinux_blob_sizes=0x02302940, .off_security_hook_heads=0x023022A8,
  .off_kmalloc_caches=0x02301DE0, .off_anon_pipe_buf_ops=0x0216A7E8,
  .off_ashmem_misc_fops=0x0291A8E8, .off_ashmem_fops=0x022BFDC8,
  .off_ashmem_ioctl=0x01837928, .off_ashmem_compat_ioctl=0x01837930,
  .off_ashmem_mmap=0x01822A68, .off_ashmem_open=0x01831488,
  .off_ashmem_release=0x01831490, .off_ashmem_show_fdinfo=0x01822BE8,
  .off_configfs_read_iter=0x0182FCF8, .off_configfs_bin_write_iter=0x01830218,
  .off_copy_splice_read=0x01822B58, .off_noop_llseek=0x0181FE48,
  .off_ashmem_llseek=0x0181FEF8, .off_ashmem_read_iter=0x01822948,
  .off_bss_tail_lock=0x02BB9D00,
  .off_cap_capable_active=0x00000000,
  .off_slide_nfulnl_logger=0x027C14B8, .off_slide_loggers_0_1=0x027C13F0,
  .off_slide_boot_id=0x02B99B6D,
  .off_system_unbound_wq=0x027B9E88,
  .off_call_usermodehelper_exec_work=0x0183E200,
),

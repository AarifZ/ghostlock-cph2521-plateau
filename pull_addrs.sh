#!/system/bin/sh
# Phase 1: extract all critical kernel addresses with root
export PATH=/system/bin:/system/xbin:$PATH

echo "=== GUARD MODULE BASE ==="
GUARDBASE=$(cat /proc/modules | grep oplus_security_guard | awk '{print $NF}' | tr -d '() ')
echo "guard_base: $GUARDBASE"

echo
echo "=== GUARD FUNCTIONS ==="
cat /proc/kallsyms | grep -E 'oplus_root_check_post_handler\s|oplus_root_check_pre_handler\s|oplus_exe_block_ret_handler\s|oplus_harden_pre_handler\s|g_boot_state' | head -8

echo
echo "=== KEY KERNEL SYMBOLS ==="
cat /proc/kallsyms | grep -E ' init_cred$| init_task$| selinux_enforcing$| selinux_state$|random_boot_id|ashmem_misc$' | head -8

echo
echo "=== THIS PROCESS TASK ==="
echo "my_pid: $$"
echo "task from stat field 28 (kstkesp):"
awk '{print $28}' /proc/$$/stat 2>/dev/null
echo "task from /proc/$$/stack:"
head -3 /proc/$$/stack 2>/dev/null

echo
echo "=== ALL MODULE BASES ==="
cat /proc/modules | grep -E 'oplus_security|oplusboot' | awk '{print $1, $NF}'

echo
echo "=== INIT TASK CRED ==="
cat /proc/kallsyms | grep -E ' init_cred$| init_task$'

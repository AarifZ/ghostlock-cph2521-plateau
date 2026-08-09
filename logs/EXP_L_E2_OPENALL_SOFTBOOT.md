# EXP L - E2 + OPEN_ALL_FDS - SOFTBOOT

- CMP_REQUEUE_PI errno=35 EDEADLK OK
- OPEN_ALL_FDS did not prevent softboot
- Last stage: place E2 stamp (parent=fake_fops right=MISC lock=fake_lock) then ADB death at/near select
- Reject: main MISC-as-right still softboot class even with all fds open
- Note: intended hardboot failed (adb reboot no device); fire ran on dirty uptime ~1083s - bad process


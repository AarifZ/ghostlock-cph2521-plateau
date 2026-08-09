# EXP V - CLASSIC_SAFE + LOCK_OWNER0 - SOFTBOOT

Source-driven: avoid wake(init_task) and setprio(fake_task) after dequeue.
Still softboot after place -> rb_erase with parent=MISC-8 is lethal itself.
Recovery: CLEAN 112515d9 then 112515d9 wait - AFTER 112515d9-d91a... no AFTER 112515d9 from V recover was 112515d9 - log says AFTER boot_id=112515d9-d91a-405a-a904-f966e3241822

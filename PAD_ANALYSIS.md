# Stamp-reach analysis (QEMU lldb, session 7)

fdset copy lands 920B BELOW the rt_waiter field slots on the waiter stack.
Userspace recursion cannot move the kernel-side copy depth (syscall frames
pop on return; entry depth is fixed per syscall). No syscall knob reaches
+920B. Therefore select-based stamping CANNOT hit the waiter in this kernel.

Options going forward:
1. sigreturn/FPSIMD stamp (Samsung 5.15 route): rt_sigreturn's frame lands
   DEEPER (signal frames) — needs RVA analysis of our rt_sigreturn +
   fpsimd simulate — candidate to reach +920B.
2. setsockopt MCAST (Quest3 route): its stack buffer depth must be measured
   the same way (lldb tags) — if within reach, port exp32's stamper.
3. Abandon stamp: exploit the SECOND-WALKER reality — the residue IS the
   rt_waiter with real (not controlled) fields; walk exits safely (QEMU
   showed clean NULL exits). No store. Not viable.

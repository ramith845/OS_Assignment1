# _entry should be the first function invoked when
# the QEMU CPU starts executing. It's location should
# according to the memory layout provided in param.h
#include "param.h"
.extern bl_stack

.section .text
.global _entry
_entry:
        # task: setup a per-CPU stack for C and jump to start() function
        la t0, bl_stack
        li t1, STSIZE
        add sp, t0, t1
        # mv sp, t0
        j start
spin:
        j spin

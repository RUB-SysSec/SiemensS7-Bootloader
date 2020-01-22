.globl _start
.globl main

.section .text.entry
.align 4
_start:
/* Must preserve regs and cpsr */
    /*stmfd sp!, {r0-r12, lr}
    adr sb, _start

    bl main

    ldmfd sp!, {r0-r12, lr}
    bx lr*/

    b main

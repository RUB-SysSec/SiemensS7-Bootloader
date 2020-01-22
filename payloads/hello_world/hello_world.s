// assembling raw shellcode: $arm-linux-gnueabi-as -EB -o tmp.elf stager.s && arm-linux-gnueabi-objcopy -j .text -Obinary tmp.elf stager.bin

	.arch armv7r
.section .text
	.align	4
	.arm
	.syntax unified
_start:
	STMFD           SP!, {R5-R12, LR}
	mov r5, r0
	mov r6, r1
	
	//ldr r2, s_okay
	//str r2, [r1]

	adr r0, s_okay
	ldr r2, fn_UART_send
	blx r2

	mov r0, 5
	LDMFD           SP!, {R5-R12, PC}

fn_UART_send:
	.word 0xD918

.align 4
s_okay:
	.ascii "\x05"
    .ascii "TEST"
.align 4
s_err:
	.ascii "\2\xff"

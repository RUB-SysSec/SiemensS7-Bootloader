#ifndef PRINT_H
#define PRINT_H

/**
 * Our implementation of printf via UART1. Define GDBSTUB_PRINT to wrap output strings in gdb stdout
 * packets.
 */

int putchar(int c);
int puts(const char* s);
void printf(char *format, ...);
int UART_protocol_send_many(const char *s, unsigned int len);
int UART_protocol_send_single(const char *s, unsigned int len);

#endif

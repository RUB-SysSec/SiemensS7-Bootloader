#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "print.h"
#include "stdlib.h"

#define BUF_LEN 16

//char print_buf[BUF_LEN] = {0}   ;
//size_t print_buf_pos = 0;

volatile uint32_t* uart2_base = (uint32_t*)0xfffb8000;
volatile uint32_t* uart2_rh = (uint32_t*)0xfffb8018;

//uint32_t gdb_chksum = 0;

//static const char hexChars[] = "0123456789abcdef";

/* Gdbstub print taken from https://github.com/espressif/esp-gdbstub */

int putchar(int c) {
    while (*uart2_rh & 0x20) {
        *(volatile uint32_t *)0xFFFBB120 = 0x967EA5C3;
    }
    *uart2_base = (uint32_t)c;
    return c;
}
/*
static
void print_flush() {
    for (size_t i = 0; i < print_buf_pos; i++)
        do_putchar(print_buf[i]);
    print_buf_pos = 0;
}

int putchar(int c) {
    print_buf[print_buf_pos++] = (char)c;
    if (print_buf_pos == BUF_LEN || c == '\n')
        print_flush();
    return c;
}

int puts(const char* s) {
    for (size_t i = 0; s[i] != '\0'; i++)
        do_putchar(s[i]);
    putchar('\n');
    return 1;
}
*/
/*
static int isdigit(int c) {
  return '0' <= c && c <= '9';
}

static size_t itoa(int32_t val, bool uns, char* dst) {
    bool neg = false;
    if (val < 0 && !uns) {
        val = -val;
        neg = true;
    }

    char* d = dst;
    do {
        unsigned char x = val % 10;
        *(d++) = '0' + x;
        val /= 10;
    } while (val > 0);

    if (neg)
        *(d++) = '-';

    size_t ret = d - dst;
    for (int i = 0; i < ret / 2; i++) {
        char tmp = dst[i];
        dst[i] = dst[ret - i - 1];
        dst[ret - i - 1] = tmp;
    }

    return ret;
}

__attribute__((__format__ (__printf__, 1, 2)))
void printf(char *format, ...) {
    char c;
    int32_t i;
    char buf[24];

    va_list a;
    va_start(a, format);
    while((c = *format++)) {
    if(c == '%') {
        while (*format == '-' || isdigit(*format))
            format++;

        switch(c = *format++) {
            case 'd':
            case 'u': {
                itoa(va_arg(a, uint32_t), c == 'u', buf);
                puts(buf);
                break;
            }
            case 's':
                puts(va_arg(a, char*));
                break;
            case 'c':
                putchar((char)va_arg(a, int));
                break;
            case 'x':
            case 'X':
                i = va_arg(a, int32_t);
                for (int sh = 28; sh >= 0; sh -= 4)
                    putchar(hexChars[(i >> sh) & 15]);
                break;
            case 0:
                return;
            default:
                goto bad_fmt;
            }
        } else
    bad_fmt:    putchar(c);
    }
    va_end(a);
}*/

//void (*_UART_send)(const unsigned char *) = (void (*)(const unsigned char *)) 0x0D918;

#define NEW_UART_SEND
// new implementation
#ifdef NEW_UART_SEND
int UART_protocol_send_single(const char *s, unsigned int size) {
    unsigned int crc_checksum = size+1;
    char c;
    volatile uint32_t rh;

    if(size>=0xff) {
        return -1;
    }

    putchar(size+1);
    for(int i = 0; i <size; ++i) {
        c = s[i];
        crc_checksum += c;
        putchar(c);
    }
    putchar((0x100-(crc_checksum & 0xff))&0xff);

    // Wait for everything to have been sent
    do
      rh = *((uint32_t *)uart2_rh);
    while ( rh & 8 );

    return size;
}

int UART_protocol_send_many(const char *s, unsigned int len) {
    #define CHUNK_SIZE 32u
    unsigned int i=0;
    unsigned int transfer_size;

    while(i<len) {
        if(len-i < CHUNK_SIZE) {
            transfer_size = len-i;
        } else {
            transfer_size = CHUNK_SIZE;
        }
        UART_protocol_send_single(s+i, transfer_size);
        i+=transfer_size;
    }
    UART_protocol_send_single((const char *)0, 0);
    return i;
}

#else
// old implementation
void (*_UART_send)(const unsigned char *) = (void (*)(const unsigned char *)) 0x0D918;
void UART_protocol_send(const char *s, unsigned int len) {
    #define CHUNK_SIZE 32u
    unsigned char buf[CHUNK_SIZE+4];
    unsigned int i=0;
    unsigned int transfer_size;

    while(i<len) {
        if(len-i < CHUNK_SIZE) {
            transfer_size = len-i;
        } else {
            transfer_size = CHUNK_SIZE;
        }
        buf[0] = transfer_size+1;
        memcpy(buf+1, s+i, transfer_size);
        _UART_send(buf);
        i+=transfer_size;
    }
}
#endif
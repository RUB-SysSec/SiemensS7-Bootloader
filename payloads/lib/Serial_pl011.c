/*
 * Copyright 2013-2014 Jonas Zaddach <zaddach@eurecom.fr>, EURECOM
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 or later.
 */

#include "Serial.h"

#define UART_PL011_BASE ((volatile uint32_t *) 0xFFFB8000)

#ifndef UART_PL011_BASE
#error Configuration value UART_PL011_BASE must be set, e.g. to ((volatile uint32_t *) 0x400D3000)
#endif 

#define UART_BASE (UART_PL011_BASE)


#define UART_REG_DATA 0
#define UART_REG_STATUS 1
#define UART_REG_FLAG 6
#define UART_REG_CONTROL 12

#define UART_STATUS_OVERRUN_ERR (1 << 3)
#define UART_STATUS_BREAK_ERR (1 << 2)
#define UART_STATUS_PARITY_ERR (1 << 1)
#define UART_STATUS_FRAMING_ERR (1 << 0)

#define UART_FLAG_TXFE (1 << 7)
#define UART_FLAG_RXFF (1 << 6)
#define UART_FLAG_TXFF (1 << 5)
#define UART_FLAG_RXFE (1 << 4)
#define UART_FLAG_BUSY (1 << 3)

#ifndef WATCHDOG_EXCITE
#define WATCHDOG_EXCITE do {*((unsigned int *)0xFFFBB120) = 0x967EA5C3;} while (0)
#endif

void Serial_init(void)
{
}

int Serial_write_byte(uint8_t data)
{
    
    while (UART_BASE[UART_REG_FLAG] & UART_FLAG_TXFF)
		WATCHDOG_EXCITE;
    
    UART_BASE[UART_REG_DATA] = (uint32_t) data;
    
    return 0;
}

int Serial_is_data_available(void)
{
    return (UART_BASE[UART_REG_FLAG] & UART_FLAG_RXFE) == 0;
}

int Serial_read_byte_blocking(void)
{
	int ret;
    while (!Serial_is_data_available())
		WATCHDOG_EXCITE;
    
	ret = UART_BASE[UART_REG_DATA];
	/* XXX: we want to make sure that we are reading the data before
	 * reading the error. We need a data barrier here.
	 */
    if (UART_BASE[UART_REG_STATUS] & 0xB)
    {
		/* reset the error */
		UART_BASE[UART_REG_STATUS] = 0;
        //TODO: some error
    }
    else
    {
        return ret;
    }
    
    return -1;
}

void Serial_flush_write()
{
    while (!(UART_BASE[UART_REG_FLAG] & UART_FLAG_TXFE))
		WATCHDOG_EXCITE;
}
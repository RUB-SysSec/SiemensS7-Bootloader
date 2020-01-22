#include <stdint.h>

#include "read.h"
#include "print.h"

#define UART_BASE ((volatile uint32_t *) 0xFFFB8000)

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

enum transmission_modes {
	TRANS_GET_LEN,
	TRANS_GET_CONTENTS
};

int is_data_available(void)
{
    return (UART_BASE[UART_REG_FLAG] & UART_FLAG_RXFE) == 0;
}

int read_byte_blocking(void)
{
	int ret;
    while (!is_data_available())
		WATCHDOG_EXCITE;
    
	ret = UART_BASE[UART_REG_DATA];
	/* XXX: we want to make sure that we are reading the data before
	 * reading the error. We need a data barrier here.
	 */
    if (UART_BASE[UART_REG_STATUS] & 0xb)
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

/*
	Read a chunk of up to 0xfe bytes to buf.
	Uses the transmission protocol to read

	Upon success, returns the number of chars read.
	Upon failure, returns a negative number
*/
int UART_protocol_recv_chunk(char *buf, int bufsize) {
	int mode = TRANS_GET_LEN;
	int val;
	int checksum;
	int len;
	int i = 0;

	while(1) {
		val = read_byte_blocking();
		if(val<0)
			continue;

		if(mode == TRANS_GET_LEN) {
			len = val;
			if(len-1 > bufsize) {
				return -2;
			}
			checksum = val;
			mode = TRANS_GET_CONTENTS;
		} else {
			if(len==i+1) {
				if((checksum+val)&0xff) {
					// Checksum check failed
					return -1;
				} else {
					// Checksum check okay
					return len-1;	
				}
			} else {
				checksum += val;
				buf[i++] = val;
			}
		}
	}
}

const char ack[] = "\x00";
const char err[] = "\xff";
/*
	Read an expected n bytes into buf.
	Wraps read_chunk to implemented long reads.

	Upon success, returns 0
	Upon failure, returns a negative number
*/
int UART_protocol_recv(char *buf, int n) {
	int num_read, i;

	for(i=0; i <= n; ) {
		num_read = UART_protocol_recv_chunk(buf+i, n-i);
		if(num_read<0) {
			UART_protocol_send_single(err, 1);
			return num_read;
		} else {
			i+=num_read;
			UART_protocol_send_single(ack, 1);
			if(num_read==0) {
				break;
			}
		}
	}

	return i;
}
#ifndef READ_H
#define READ_H

/*
	Read a chunk of up to 0xfe bytes to buf.
	Uses the transmission protocol to read

	Upon success, returns the number of chars read.
	Upon failure, returns a negative number
*/
int UART_protocol_recv_chunk(char *buf, int bufsize);

/*
	Read an expected n bytes into buf.
	Wraps read_chunk to implemented long reads.

	Upon success, returns 0
	Upon failure, returns a negative number
*/
int UART_protocol_recv(char *buf, int n);

#endif
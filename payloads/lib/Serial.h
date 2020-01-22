/*
 * Copyright 2013-2014 Jonas Zaddach <zaddach@eurecom.fr>, EURECOM
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 or later.
 */

#ifndef _SERIAL_H
#define _SERIAL_H

#include <stdint.h>

/**
 * Initialize the hardware to sane defaults.
 * (E.g. the baudrate and configuration expected by the communication partner)
 */
void Serial_init();

/**
 * Read one byte from the serial port.
 * If the read buffer is currently empty, wait until
 * data is available.
 * @return character (0 <= char < 256) or negative error code.
 */
int Serial_read_byte_blocking();

/**
 * Check if the next read will not block.
 * @return 0 if the next read will block, 1 otherwise.
 */
int Serial_is_next_read_blocking();

/**
 * Write one byte to the serial port.
 * This function is supposed to block if the write buffer is full,
 * and to return as soon as the byte has been successfully written
 * to the buffer.
 * @return 0 on success or negative error code.
 */
int Serial_write_byte(uint8_t data);

/**
 * Block until all data has been definitely sent.
 */
void Serial_flush_write();

#endif /* _SERIAL_H */
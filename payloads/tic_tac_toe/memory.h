// This address is the one used by bl_UART_hook_14_print_flash_contents to store firmware contents
//void *RW_BUF = (void *) 0x10036910;

// This address specifies contents after bootloader memory and does not seem to be used
char *RW_BUF = (char *) 0x00020000;
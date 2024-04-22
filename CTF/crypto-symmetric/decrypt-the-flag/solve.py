import json
import os

import random

from Crypto.Util.number import long_to_bytes

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
import base64

server = pwn.remote("130.192.5.212", 6561)

# skip first line
print(server.recvline().decode())
# send the seed
server.sendline("10".encode())
print(server.recvline().decode())

# get the ciphertext -> flag
ciphertext = bytes.fromhex(server.recvline().decode().strip())
print(ciphertext)

# generate a plaintext with the same length of the ciphertext's length
plaintext2 = b'1' * len(ciphertext)

# answer for encrypting again
server.sendline(b"y")
server.sendline(plaintext2)

ciphertext_2 = server.recvline().decode().strip().split('? ')[2]
print(ciphertext_2)
ciphertext_2 = bytes.fromhex(ciphertext_2)

# the following is possible because the nonce is always the same
# since we know plaintext and ciphertext, if we xor together we get the keystream back
# keystream ^ plaintext -> ciphertext if we reverse the effect of xor we get the keystream
keystream = bytearray()
for p, c in zip(plaintext2, ciphertext_2):
    keystream.append(p ^ c)

# to decrypt the flag ciphertext we can now xor it with the keystream ad get back the flag plaintext
flag = bytearray()
for k, c in zip(keystream, ciphertext):
    flag.append(k ^ c)

print(flag.decode())


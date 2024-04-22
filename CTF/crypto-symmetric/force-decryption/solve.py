import json
import os

from Crypto.Util.number import long_to_bytes

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
import base64

leak = b"mynamesuperadmin"
server = pwn.remote("130.192.5.212", 6523)

# skip menu
for output in server.recvlines(5):
    print(output.decode())

server.sendline(b"enc")

print(server.recvline().decode())
plaintext = long_to_bytes(0, 16)
server.sendline(plaintext.hex().encode())

iv = bytes.fromhex(server.recvline().decode().strip().split(": ")[1])
ciphertext = bytes.fromhex(server.recvline().decode().strip().split(": ")[1])
print(iv)
print(ciphertext)

tmp = bytearray()
for i, p in zip(iv, plaintext):
    tmp.append(i ^ p)

mod_cipher = bytearray()
for l, t in zip(leak, tmp):
    mod_cipher.append(l ^ t)

# skip empty returned line
print(server.recvline().decode())
# skip menu
for output in server.recvlines(5):
    print(output.decode())

server.sendline(b"dec")
print(server.recvline().decode())

server.sendline(ciphertext.hex().encode())
# send IV
print(server.recvline().decode())
server.sendline(mod_cipher.hex().encode())
print(server.recvline().decode())

server.close()
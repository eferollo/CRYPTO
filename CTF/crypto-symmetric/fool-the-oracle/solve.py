import json
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
import base64

server = pwn.remote("130.192.5.212", 6541)

for output in server.recvlines(4):
    print(output.decode())

server.sendline(b"enc")
server.sendline(b"ciao")
print(server.recvline().decode())



import json
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

server = pwn.remote("130.192.5.212", 6551)

true = b"true}"

username = b'{"username": "'
role = b'", "admin": '

pad1 = b'.' * (AES.block_size - len(username))
pad2 = pad(true, AES.block_size)
pad3 = b'.' * (AES.block_size - len(role))
tosend = pad1+pad2

js = json.dumps({
    "username": tosend.decode(),
    "admin": False
})

print(js)

# Hi, please tell me your name! -> provide name
print(server.recvline().decode())
server.sendline(tosend)

# Get the plaintext token
plain_token = server.recvline().decode().strip().split(" ")[-1]
plain_token = base64.b64decode(plain_token)

# construct token
token = plain_token[:48] + plain_token[16:32]
token = base64.b64encode(token).decode()

# skip the menu
for output in server.recvlines(4):
    print(output.decode())
server.sendline(b"flag")

# skip "What is your token"
print(server.recvline().decode())
server.sendline(token.encode())

for output in server.recvlines(10):
    print(output.decode())



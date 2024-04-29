from Crypto.Util.number import long_to_bytes, bytes_to_long
import pwn
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

server = pwn.remote("130.192.5.212", 6551)

want = b"True}"

token = json.dumps({
    "username": "aaaa",
    "admin": False
})

fixed1 = b'{"username": "'

fixed2 = b'", "admin": '

p1 = b"a" * (AES.block_size - len(fixed1))
p2 = pad(want, AES.block_size)  # b" " * (AES.block_size - len(want)) + want
p3 = b"a" * (AES.block_size - len(fixed2))
bait = p1 + p2
print(bait.decode())
x = json.dumps({
    "username": bait.decode(),
    "admin": False
})

# x = pad(x.encode(), 16)

# print(x)
# x = unpad(x, 16)
# print(len(x))


print(x)
print(token)
print(bait)
print(server.recvline())

server.sendline(bait)
token = server.recvline().decode().strip().split(" ")[-1]
token = base64.b64decode(token)
print(len(token))
print(server.recvline())

new_token = token[:48] + token[16:32]
new_token = base64.b64encode(new_token).decode()

print(server.recvline())
print(server.recvline())
print(server.recvline())

server.sendline(b"flag")

print(server.recvline())


server.sendline(new_token.encode())

for mex in server.recvlines(10):
    print(mex)


server.close()
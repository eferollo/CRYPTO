import json
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
import base64

server = pwn.remote("130.192.5.212", 6521)

mod = json.dumps({"admin": True})
mod = mod.encode()
print(mod)

# Hi, please tell me your name! -> provide name
print(server.recvline().decode())
server.sendline("userA".encode())

# Get the plaintext token
plain_token = server.recvline().decode().strip().split("> ")[1]
plain_token = bytearray(plain_token.encode())
print(plain_token)

# nonce + token (nonce.token)
rec_data = server.recvline().decode().strip().split(": ")[1]
nonce, enc_token = rec_data.split(".")
print("Nonce= " + nonce)
print("Token= " + enc_token)
# decode from base64
enc_token = base64.b64decode(enc_token)
print(f"Token decoded from base64= {enc_token}")

# skip the menu
for output in server.recvlines(4):
    print(output.decode())

# send option flag
server.sendline("flag".encode())
# skip "What is your token"
print(server.recvline().decode())

# if we xor enc_token and plain_token we get the keystream back
# by xoring again with the mod json we apply the keystream on it as if it was applied on the server
# this is possible because then we use the same nonce to decrypt (and the same key on the server) -> same keystream
token = bytearray()
for t_b, p_b, m_b in zip(enc_token, plain_token, mod):
    token.append(t_b ^ m_b ^ p_b)

# put together nonce and token in the format nonce.token
token = base64.b64encode(token).decode()
tosend = f"{nonce}.{token}"
print(tosend)

# send token to the server
server.sendline(tosend.encode())
for output in server.recvlines(3):
    print(output.decode())

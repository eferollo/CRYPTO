import os
from Crypto.Util.number import long_to_bytes
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn


leak = b"mynamesuperadmin"
server = pwn.remote("130.192.5.212", 6523)

# skip menu
for output in server.recvlines(5):
    print(output.decode())

server.sendline(b"enc")
# skip message
print(server.recvline().decode())

# send a null plaintext (1 block of all 0s)
plaintext = long_to_bytes(0, 16)
server.sendline(plaintext.hex().encode())

# From the server I get the IV and the ciphertext = enc(key, 0s) ^ IV
iv = bytes.fromhex(server.recvline().decode().strip().split(": ")[1])
ciphertext = bytes.fromhex(server.recvline().decode().strip().split(": ")[1])
print(iv)
print(ciphertext)

# with leak ^ IV I solve one step
mod_cipher = bytearray()
for l, t in zip(leak, iv):
    mod_cipher.append(l ^ t)

# skip empty returned line
print(server.recvline().decode())
# skip menu
for output in server.recvlines(5):
    print(output.decode())

server.sendline(b"dec")
# skip message
print(server.recvline().decode())
# In this case is like sending the key xored with IV
server.sendline(ciphertext.hex().encode())

# send IV -> as IV I will send the leak ^ IV
# dec(key, cipher) ^ (leak ^ IV)
# (0s ^ IV) ^ (leak ^ IV) = (0s ^ leak) = leak
# I removed the effect of the IV and xoring the leak with 0s has no effect
print(server.recvline().decode())
server.sendline(mod_cipher.hex().encode())

# flag result
print(server.recvline().decode())
server.close()
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
from Crypto.Util.number import long_to_bytes

server = pwn.remote("130.192.5.212", 6645)

# receive modulus n and ciphertext c from the server
n = int(server.recvline().decode())
c = int(server.recvline().decode())
e = 65537

# ((2^e % n) * c) % n = ((2^e % n) * (m^e % n)) % n
# c = m^e % n -> c' = 2^e * c = 2^e * m^e (%n) = (2m)^e (%n) -> during decryption we avoid to be m but instead is 2m
# so to get m we need just to // 2 the result
tosend = (pow(2, e, n) * c) % n

server.sendline(b'd'+str(tosend).encode())

bit = int(server.recvline().decode())
bit = bit // 2

print(long_to_bytes(bit).decode())

import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
import pwn
from Crypto.Util.number import long_to_bytes

server = pwn.remote("130.192.5.212", 6646)

c = int(server.recvline().decode())
e = 65537

# We send 2 in order to get (2^e % n) encryption (in this case we don't have the modulus)
server.sendline(b'e' + str(2).encode())
pow2 = int(server.recvline().decode())

# Same strategy as challenge 5 -> c' = ((2^e %n) * (m^e %n)) -> 2m -< divide by // 2 and get the flag
c_2m = pow2 * c
server.sendline(b'd' + str(c_2m).encode())

bit = int(server.recvline().decode())
bit = bit // 2

print(long_to_bytes(bit).decode())
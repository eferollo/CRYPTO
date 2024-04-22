from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes

key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'
IV = get_random_bytes(16)
print(IV)
cipher = AES.new(key, AES.MODE_CBC, IV=IV)
plaintext = long_to_bytes(0, 16)
ciphertext = cipher.encrypt(plaintext)
print(ciphertext)

leak = b"mynamesuperadmin"
mod_cipher = bytearray()
for l, t in zip(leak, IV):
    mod_cipher.append(l ^ t)

cipher = AES.new(key, AES.MODE_CBC, IV=mod_cipher)
result = cipher.decrypt(ciphertext)
print(result)
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20
import base64

if __name__ == '__main__':

    plaintext = b'This is a secret message...'
    plaintext_2 = b'This is additional text to encrypt'

    key = get_random_bytes(ChaCha20.key_size)
    nonce = get_random_bytes(12)
    print("Nonce = " + base64.b64encode(nonce).decode())

    cipher = ChaCha20.new(key = key, nonce = nonce)

    ciphertext = cipher.encrypt(plaintext)
    ciphertext += cipher.encrypt(plaintext_2) # can be called multiple times

    print("Ciphertext = " + base64.b64encode(ciphertext).decode())
    print("Nonce = " + base64.b64encode(cipher.nonce).decode())



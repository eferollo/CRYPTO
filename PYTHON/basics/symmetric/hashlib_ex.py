import hashlib
import hmac

from Crypto.Random import get_random_bytes

if __name__ == '__main__':
    dig_geerator = hashlib.sha256()
    dig_geerator.update(b'First chunck of data')
    dig_geerator.update(b'Second chunck of data')

    print(dig_geerator.hexdigest())

    secret = get_random_bytes(32)

    mac_generator = hmac.new(secret, b'Message to hash', hashlib.sha256)

    hmac_sender = mac_generator.hexdigest()
    print(hmac_sender)

    # ---------- at verifier

    mac_gen_rec = hmac.new(secret, b'Message to hash', hashlib.sha256)
    hmac_ver = mac_gen_rec.hexdigest()

    if hmac.compare_digest(hmac_sender, hmac_ver):
        print("HMACS are OK")
    else:
        print("HMACS are different")

import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
import requests
import time

session = requests.Session()
response = session.get('http://130.192.5.212:6522/login?username=b&admin=1')

# compute actual time
now_time = time.time()
date = int(now_time) + 30 * 24 * 60 * 60
date = str(date).encode()
print(date)

# extract the content of the json
js = json.loads(response.content.decode())
print(js)
cookie = int(js['cookie'])
nonce = int(js['nonce'])
cookie = long_to_bytes(cookie)

keydate_cipher = cookie[19:29]  # get the "&expires="

# admin_expire_time is computed starting from the actual time of the code execution
# (near to the user time) minus a random number of days between 10 and 266
# the flag is returned only if the expiration time of the token minus the admin_expire_time
# is between 290 and 300
# we need to try to add the time randomly subtracted by the server on the admin_expire_time
for i in range((290 - 266), (300 - 10)):
    #print(i)
    offset = str(now_time + i * (24 * 60 * 60)).encode()

    mod = bytearray()
    for a, b, c in zip(offset, keydate_cipher, date):
        mod.append(a ^ b ^ c)

    cookie_tosend = cookie[:19] + mod + cookie[29:]
    cookie_tosend = bytes_to_long(cookie_tosend)

    response = session.get(f'http://130.192.5.212:6522/flag?nonce={nonce}&cookie={cookie_tosend}')
    print(response.content)


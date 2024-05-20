from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

# factordb strategy
# The two prime numbers computed at server side are small (64) so I can factorize n with factorDB to get them

f = FactorDB(180210299477107234107018310851575181787)
f.connect()
p, q = f.get_factor_list()

# Recompute n = p*q
n = p*q
e = 65537

# Calculate the private exponent d since I have both p and q and use it for computing the message by c^d % n
phi = (p-1) * (q-1)
d = pow(e, -1, phi)

c = 27280721977455203409121284566485400046

m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode())

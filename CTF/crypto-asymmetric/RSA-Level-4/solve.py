from Crypto.Util.number import long_to_bytes

# strategy common modulus
# On server side the encrypted flag is computed two times with the same modulus n.
# c1 = m^e1 % n
# c2 = m^e2 % n
# With bezout identity we can find e1*u + e2*v = gcd(e1,e2) -> Since gcd is 1 then (c1^u % n) * (c2^v % n) % n = flag
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

n = 74127062592257379832681970870208459545927212876474945408181055721483431144118749449983805496907327519686009984113230515437169786731373036071335230064283343801130988057490937279732537899866535311631000990092668325335053279896045043314501128208259798187003002650817314007262825084594642234582964348500474384789
c1 = 24226980988773997507073115936081752432469234074309070603829150651361400993090238408437733187516125091349349900636015110297875050668189314924814632263843789027833184643836128394396861399990327927221587362355128056287769156124240066559919680659298140935321396733182876952727302612009590208802133940956113028197
c2 = 11894067048854576466109342934305835296168604754031192140834815754346495031539560484115416761045937477048684043863029512406579476058237650009484290949671784749114768244628343374294343124582303966158022954978947123786419579160186053349059585106024649979366538138598020496831198952443712050184382867584908984705
e1 = 31
e2 = 71

(g, u, v) = egcd(e1, e2)

m = pow(c1, u, n) * pow(c2, v, n) % n
flag = long_to_bytes(m)
print(flag.decode())

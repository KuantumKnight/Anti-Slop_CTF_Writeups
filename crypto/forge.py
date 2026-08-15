import hashlib, re
from poly import conn, cmd
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
n=SECP256k1.order; G=SECP256k1.generator
d=0xc08a9e9a991e6710dd121ddd3e7b4431bc8d71fc1f83570c9fbabf9c7c59a6b4  # diagkey priv
def grant_z(W):
    msg=b'POLYPHASE|grant|'+W.to_bytes(8,'big')
    h=hashlib.sha256(msg).digest()
    return int.from_bytes(h,'big')%n, msg
def sign(z,k=0x123456789abcdef):
    R=k*G; r=R.x()%n
    s=(inverse_mod(k,n)*(z+r*d))%n
    return r,s
s,banner=conn()
sid=int(re.search(r'sid=(\d+)',banner).group(1))
print('sid=',sid)
for label,W in [('sid_be',sid),('zero',0),('sid_le',int.from_bytes(sid.to_bytes(8,'big'),'little')),('commits0',0)]:
    z,msg=grant_z(W)
    r,sg=sign(z)
    sig=format(r,'064x')+format(sg,'064x')
    resp=cmd(s,'auth '+sig)
    print(f'W={label}({W}) msg={msg} -> {resp}')
s.close()

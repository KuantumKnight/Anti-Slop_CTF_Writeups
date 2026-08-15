import json
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
from ecdsa.ellipticcurve import Point
cur=SECP256k1;n=cur.order;G=cur.generator;p=cur.curve.p()
def dec(h):
    pre=h[:2];x=int(h[2:],16)
    y=pow((pow(x,3,p)+7)%p,(p+1)//4,p)
    if (y%2==0)!=(pre=='02'):y=p-y
    return Point(cur.curve,x,y)
diag=dec('03cd06cc525630a52d01604f904536e46a6ddfd7c7a4c1a3488c94ed34bc28680b')
pub=dec('02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488')
data=json.load(open('diag.json'))
def verify(Q,z,r,s):
    w=inverse_mod(s,n); u1=z*w%n; u2=r*w%n
    R=u1*G+u2*Q
    return (R.x()%n)==r
e=list(data)[3]; rec=data[e]
z=int(rec['z'],16); sig=rec['sig']; r=int(sig[:64],16); s=int(sig[64:],16)
print('diag epoch',e)
print('z as-is under diagkey:', verify(diag,z%n,r,s))
print('z as-is under pubkey :', verify(pub,z%n,r,s))

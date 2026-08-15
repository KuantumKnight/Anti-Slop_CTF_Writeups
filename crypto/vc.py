import json
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
from ecdsa.ellipticcurve import Point
cur=SECP256k1;n=cur.order;G=cur.generator;p=cur.curve.p()
def dec(h):
    pre=h[:2];x=int(h[2:],16);y=pow((pow(x,3,p)+7)%p,(p+1)//4,p)
    if (y%2==0)!=(pre=='02'):y=p-y
    return Point(cur.curve,x,y)
pub=dec('02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488')
diag=dec('03cd06cc525630a52d01604f904536e46a6ddfd7c7a4c1a3488c94ed34bc28680b')
def ver(Q,z,r,s):
    w=inverse_mod(s,n);return (((z*w%n)*G+(r*w%n)*Q).x()%n)==r
rows=json.load(open('commit.json'))['rows']
x=rows[0]; z=int(x['digest'],16)%n; r=int(x['sig'][:64],16); s=int(x['sig'][64:],16)
print('commit sig under pubkey :',ver(pub,z,r,s))
print('commit sig under diagkey:',ver(diag,z,r,s))
# also try z without mod
z2=int(x['digest'],16)
print('z full under pubkey:',ver(pub,z2%n,r,s))

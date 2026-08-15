from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
cur=SECP256k1; n=cur.order; G=cur.generator; p=cur.curve.p()
def dec(h):
    pre=h[:2];x=int(h[2:],16);a=cur.curve.a();b=cur.curve.b()
    y=pow((pow(x,3,p)+a*x+b)%p,(p+1)//4,p)
    if (y%2==0)!=(pre=='02'):y=p-y
    return Point(cur.curve,x,y)
pub=dec('02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488')
diag=dec('03cd06cc525630a52d01604f904536e46a6ddfd7c7a4c1a3488c94ed34bc28680b')
c0=0x7ba21ce663dbfa7c32810fafa0ee3cc064027154924c7ac85b3ca65cdd184c4
c1=0xd6c2e2313691f923e983579e3c3872a23cc68a8fe269e42419d42e9b7d4032b5
c2=0x1503a10b49e3542d25422456151ef52ead9f463f336ddb3afa852adb1abd69cd
d=0xc08a9e9a991e6710dd121ddd3e7b4431bc8d71fc1f83570c9fbabf9c7c59a6b4
def px(P): return P.x()
cands={'c0':c0,'c1':c1,'c2':c2,'d':d,'c0+c1':(c0+c1)%n,'c0+c1+c2':(c0+c1+c2)%n,
 'c0-c1':(c0-c1)%n,'c0*c1':(c0*c1)%n,'d+c0':(d+c0)%n,'d-c0':(d-c0)%n,'d*c0':(d*c0)%n,
 'c1-c0':(c1-c0)%n,'c2-c1':(c2-c1)%n,'d^c0':(d^c0)%n,'2c2':(2*c2)%n,'c0+c2':(c0+c2)%n,
 'd+c1':(d+c1)%n,'d+c2':(d+c2)%n}
for nm,v in cands.items():
    P=(v%n)*G
    if P.x()==pub.x(): print('PUBKEY =',nm,'* G  !!!', hex(v%n))
    if P.x()==diag.x(): print('DIAGKEY =',nm,'* G')
print('done scan')

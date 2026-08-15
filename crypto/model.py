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
rows=json.load(open('commit.json'))['rows']
def test(model,label):
    # model(i)->c_i (the nonce minus d*coeff?) we solve d from k=d+c_i
    ds=set()
    for x in rows:
        i=x['commit']; z=int(x['digest'],16)%n; r=int(x['sig'][:64],16); s=int(x['sig'][64:],16)
        ci=model(i)%n
        # k=d+ci: s*(d+ci)=z+r*d -> d*(s-r)=z-s*ci
        denom=(s-r)%n
        if denom==0: continue
        d=((z-s*ci)*inverse_mod(denom,n))%n
        ds.add(d)
    # if all same d and matches pub -> win
    for d in ds:
        if (d*G).x()==pub.x(): return d,label
    # check consistency: all ds equal?
    return (None, f"{label}: {len(ds)} distinct d (need 1)")
models=[('k=d+counter',lambda i:i),('k=d+counter-1',lambda i:i-1),('k=d-counter',lambda i:-i),
 ('k=d+counter^2',lambda i:i*i),('k=d*counter inv?',lambda i:0)]
for m,l in models:  # m=label,l=func
    r=test(l,m);
    if r[0]: print('FOUND',l,hex(r[0]));break
    else: print(r[1])
# also k=d*counter: s*d*i = z + r*d -> d*(s*i - r)=z -> d=z/(s*i-r)
def test_mul(label,f):
    for x in rows:
        i=f(x['commit']); z=int(x['digest'],16)%n; r=int(x['sig'][:64],16); s=int(x['sig'][64:],16)
        denom=(s*i-r)%n
        if denom==0: continue
        d=(z*inverse_mod(denom,n))%n
        if (d*G).x()==pub.x(): print('FOUND',label,hex(d));return True
    return False
test_mul('k=d*counter',lambda i:i)
test_mul('k=d*(counter+1)',lambda i:i+1)
print('done')

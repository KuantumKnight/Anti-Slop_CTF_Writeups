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
rows=json.load(open('commit2.json'))
def solve(A,b,n):
    A=[r[:] for r in A]; b=b[:]; m=len(A); cols=len(A[0]); row=0; piv=[]
    for col in range(cols):
        sel=-1
        for r in range(row,m):
            if A[r][col]%n: sel=r;break
        if sel<0: continue
        A[row],A[sel]=A[sel],A[row]; b[row],b[sel]=b[sel],b[row]
        iv=inverse_mod(A[row][col],n); A[row]=[x*iv%n for x in A[row]]; b[row]=b[row]*iv%n
        for r in range(m):
            if r!=row and A[r][col]%n:
                f=A[r][col]; A[r]=[(A[r][i]-f*A[row][i])%n for i in range(cols)]; b[r]=(b[r]-f*b[row])%n
        piv.append((row,col)); row+=1
        if row==m: break
    sol=[None]*cols
    for r,c in piv: sol[c]=b[r]%n
    return sol
def idx_preview(x): return int(x['preview'],16)
def idx_epoch(x): return x['epoch']
def idx_a(x): return x['a']
for name,idx in [('preview',idx_preview),('epoch',idx_epoch),('a',idx_a)]:
    for deg in range(1,8):
        A=[];bb=[]
        for x in rows:
            i=idx(x)%n; z=int(x['digest'],16)%n; r=int(x['sig'][:64],16); s=int(x['sig'][64:],16)
            A.append([s*pow(i,j,n)%n for j in range(deg+1)]+[(-r)%n]); bb.append(z)
        if len(A)<deg+2: continue
        sol=solve(A,bb,n)
        if sol[-1] is None: continue
        d=sol[-1]%n
        ok=all((sum(sol[j]*pow(idx(x),j,n) for j in range(deg+1))*int(x['sig'][64:],16)-int(x['sig'][:64],16)*d-int(x['digest'],16))%n==0 for x in rows)
        if ok and (d*G).x()==pub.x():
            print('*** WIN',name,'deg',deg,hex(d));break
        if ok: print(name,'deg',deg,'consistent but d*G!=pub',hex(d))
print('done')

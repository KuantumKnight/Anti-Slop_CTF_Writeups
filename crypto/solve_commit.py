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
d=json.load(open('commit.json')); rows=d['rows']
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
# index basis: try i = commit counter, and i = counter-1
for basekey,baseval in [('counter',lambda x:x['commit']),('counter-1',lambda x:x['commit']-1)]:
    for deg in range(1,7):
        A=[];bb=[]
        for x in rows:
            i=baseval(x); z=int(x['digest'],16)%n; r=int(x['sig'][:64],16); s=int(x['sig'][64:],16)
            A.append([s*pow(i,j,n)%n for j in range(deg+1)]+[(-r)%n]); bb.append(z)
        if len(A)<deg+2: continue
        sol=solve(A,bb,n)
        if sol[-1] is None: continue
        dd=sol[-1]%n
        ok=all((sum(sol[j]*pow(baseval(x),j,n) for j in range(deg+1))*int(x['sig'][64:],16)-int(x['sig'][:64],16)*dd-int(x['digest'],16))%n==0 for x in rows)
        if ok:
            Q=dd*G; tag=''
            if Q.x()==pub.x(): tag='*** MAIN PUBKEY ***'
            if Q.x()==diag.x(): tag='*** DIAGKEY ***'
            print(f'{basekey} deg={deg} consistent d={hex(dd)} {tag}')

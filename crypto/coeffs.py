import json
from ecdsa import SECP256k1
from ecdsa.numbertheory import inverse_mod
data=json.load(open('diag.json'))
pts={int(k):v for k,v in data.items()}
n=SECP256k1.order; G=SECP256k1.generator
def solve(A,b,n):
    A=[r[:] for r in A]; b=b[:]; m=len(A); cols=len(A[0]); row=0; piv=[]
    for col in range(cols):
        sel=-1
        for r in range(row,m):
            if A[r][col]%n: sel=r;break
        if sel<0: continue
        A[row],A[sel]=A[sel],A[row]; b[row],b[sel]=b[sel],b[row]
        iv=inverse_mod(A[row][col],n); A[row]=[(x*iv)%n for x in A[row]]; b[row]=b[row]*iv%n
        for r in range(m):
            if r!=row and A[r][col]%n:
                f=A[r][col]; A[r]=[(A[r][i]-f*A[row][i])%n for i in range(cols)]; b[r]=(b[r]-f*b[row])%n
        piv.append((row,col)); row+=1
        if row==m: break
    sol=[None]*cols
    for r,c in piv: sol[c]=b[r]%n
    return sol
deg=2
A=[];b=[]
for i in sorted(pts):
    z=int(pts[i]['z'],16); sig=pts[i]['sig']; r=int(sig[:64],16); s=int(sig[64:],16)
    A.append([(s*pow(i,j,n))%n for j in range(deg+1)]+[(-r)%n]); b.append(z%n)
sol=solve(A,b,n)
c0,c1,c2,d=sol
print('c0=',hex(c0)); print('c1=',hex(c1)); print('c2=',hex(c2)); print('d =',hex(d))
# check small / interesting
for nm,v in [('c0',c0),('c1',c1),('c2',c2)]:
    print(nm,'bitlen',v.bit_length())

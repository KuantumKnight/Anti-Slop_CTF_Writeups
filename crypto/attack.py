import json
from ecdsa import SECP256k1, NIST256p
from ecdsa.numbertheory import inverse_mod

data=json.load(open('diag.json'))
pts={int(k):v for k,v in data.items()}

def solve_linear_mod(A,b,n):
    # Gaussian elimination mod n (n prime)
    m=len(A); cols=len(A[0])
    A=[row[:] for row in A]; b=b[:]
    row=0
    piv=[]
    for col in range(cols):
        # find pivot
        sel=-1
        for r in range(row,m):
            if A[r][col]%n!=0: sel=r; break
        if sel<0: continue
        A[row],A[sel]=A[sel],A[row]; b[row],b[sel]=b[sel],b[row]
        inv=inverse_mod(A[row][col],n)
        A[row]=[(x*inv)%n for x in A[row]]; b[row]=(b[row]*inv)%n
        for r in range(m):
            if r!=row and A[r][col]%n!=0:
                f=A[r][col]
                A[r]=[(A[r][i]-f*A[row][i])%n for i in range(cols)]
                b[r]=(b[r]-f*b[row])%n
        piv.append((row,col)); row+=1
        if row==m: break
    sol=[None]*cols
    for r,c in piv: sol[c]=b[r]%n
    return sol

for curve,name in [(SECP256k1,'secp256k1'),(NIST256p,'P-256')]:
    n=curve.order; G=curve.generator
    for deg in range(1,9):
        unknowns=deg+1+1  # c_0..c_deg (deg+1) + d
        # need at least `unknowns` eqs; use all available
        idxs=sorted(pts)
        A=[]; b=[]
        for i in idxs:
            z=int(pts[i]['z'],16); sig=pts[i]['sig']
            r=int(sig[:64],16); s=int(sig[64:],16)
            # s*(sum c_j i^j) - r*d = z   (mod n)
            row=[(s*pow(i,j,n))%n for j in range(deg+1)] + [(-r)%n]
            A.append(row); b.append(z%n)
        sol=solve_linear_mod(A,b,n)
        if sol[-1] is None: continue
        d=sol[-1]%n
        # verify against diagkey
        Q=d*G
        comp=('02' if Q.y()%2==0 else '03')+format(Q.x(),'064x')
        diagkey='03cd06cc525630a52d01604f904536e46a6ddfd7c7a4c1a3488c94ed34bc28680b'
        pubkey='02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488'
        tag=''
        if comp==diagkey: tag='*** MATCHES DIAGKEY ***'
        if comp==pubkey: tag='*** MATCHES PUBKEY ***'
        # check consistency: does this d satisfy all eqs?
        ok=all((sum(sol[j]*pow(i,j,n) for j in range(deg+1))*int(pts[i]['sig'][64:],16) - (int(pts[i]['sig'][:64],16)*d) - int(pts[i]['z'],16))%n==0 for i in idxs)
        if tag or ok:
            print(f"{name} deg={deg} consistent={ok} d={hex(d)} {tag} comp={comp[:20]}")

# relationship between pubkey and diagkey
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
curve=SECP256k1; n=curve.order; G=curve.generator; p=curve.curve.p()
def decomp(h):
    pre=h[:2]; x=int(h[2:],16)
    a=curve.curve.a(); b=curve.curve.b()
    y2=(pow(x,3,p)+a*x+b)%p
    y=pow(y2,(p+1)//4,p)
    if (y%2==0)!=(pre=='02'): y=p-y
    return Point(curve.curve,x,y)
dk=decomp('03cd06cc525630a52d01604f904536e46a6ddfd7c7a4c1a3488c94ed34bc28680b')
pk=decomp('02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488')
d=0xc08a9e9a991e6710dd121ddd3e7b4431bc8d71fc1f83570c9fbabf9c7c59a6b4
print('d*G==diagkey:', (d*G).x()==dk.x())
# is pubkey = pk relation to d?
for off in range(-5,6):
    if (((d+off)%n)*G).x()==pk.x(): print('pubkey priv = d_diag +',off)
print('pubkey == diag + G?', (dk+G).x()==pk.x())
print('pubkey == diag - G?', (dk+(-1*G)).x()==pk.x())
# polynomial coeffs

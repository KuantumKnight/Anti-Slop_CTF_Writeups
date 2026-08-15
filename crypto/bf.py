import socket, time
HOST,PORT='178.105.199.41',20006
def conn():
    s=socket.socket(); s.connect((HOST,PORT)); s.settimeout(2.0)
    buf=b''
    while b'quit' not in buf:
        buf+=s.recv(4096)
    return s
def cmd(s,c):
    s.sendall((c+'\n').encode())
    buf=b''
    while True:
        try: d=s.recv(4096)
        except socket.timeout: break
        if not d: break
        buf+=d
        if b'\n' in d: break
    return buf.decode(errors='replace').strip()
def hdr(body,chk,b7=0,b8=0,b10=0,b11=0):
    body=bytes(body); n=len(body)
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([b7,b8,chk,b10,b11])+body).hex()
prog=[0x10,0x41,0x27]
s=conn()
found=None
for chk in range(256):
    r=cmd(s,'load '+hdr(prog,chk))
    if 'checksum' not in r:
        print('chk=0x%02x ->'%chk, r); found=chk; break
if found is not None:
    print('dryrun:',cmd(s,'dryrun'))
    print('commit:',cmd(s,'commit'))
    print('info:',cmd(s,'info'))
else:
    print('NO checksum matched; sample resp:', cmd(s,'load '+hdr(prog,0)))
s.close()

import socket
HOST,PORT='178.105.199.41',20006
def conn():
    s=socket.socket(); s.connect((HOST,PORT)); s.settimeout(3.0)
    buf=b''
    while b'quit' not in buf: buf+=s.recv(4096)
    return s,buf.decode(errors='replace')
def cmd(s,c,n=1):
    s.sendall((c+'\n').encode()); buf=b''
    while True:
        try: d=s.recv(4096)
        except socket.timeout: break
        if not d: break
        buf+=d
        if buf.endswith(b'\n'): break
    return buf.decode(errors='replace').strip()
def cap(body,b8=0,b9=0,b10=0,b11=0):
    body=bytes(body); n=len(body)
    chk=sum(body[j]^((0x17*j)&0xff) for j in range(n))&0xff
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([chk,b8,b9,b10,b11])+body).hex()
if __name__=='__main__':
    s,banner=conn()
    print('BANNER:',banner.strip())
    prog=[0x10,0x41,0x27]   # push8 0x41 ; emit
    print('load:',cmd(s,'load '+cap(prog)))
    print('dryrun:',cmd(s,'dryrun'))
    print('commit:',cmd(s,'commit'))
    print('info:',cmd(s,'info'))
    s.close()

def asm(ops):
    # ops: list of opcode bytes (the deobfuscated program). raw[j]=op^ks, ks=0x17*j
    raw=bytes([(ops[j]^((0x17*j)&0xff))&0xff for j in range(len(ops))])
    n=len(raw); chk=sum(ops)&0xff   # = sum(raw^ks)
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([chk,0,0,0,0])+raw).hex()

import socket
HOST,PORT='178.105.199.41',20006
def conn():
    s=socket.socket(); s.connect((HOST,PORT)); s.settimeout(2.0)
    buf=b''
    while b'quit' not in buf: buf+=s.recv(4096)
    return s
def cmd(s,c):
    s.sendall((c+'\n').encode()); buf=b''
    while True:
        try: d=s.recv(4096)
        except socket.timeout: break
        if not d: break
        buf+=d
        if buf.endswith(b'\n'): break
    return buf.decode(errors='replace').strip()
def raw(body,b7,b8,b9,b10,b11):
    body=bytes(body);n=len(body)
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([b7,b8,b9,b10,b11])+body).hex()
s=conn()
prog=[0x10,0x41,0x27]
# sweep each header slot individually for prog, others 0
for slot in [7,8,9,10,11]:
    hits=[]
    for v in range(256):
        bb=[0,0,0,0,0]; bb[slot-7]=v
        r=cmd(s,'load '+raw(prog,*bb))
        if 'checksum' not in r: hits.append((hex(v),r))
    print(f'slot{slot} hits:',hits[:6])
s.close()

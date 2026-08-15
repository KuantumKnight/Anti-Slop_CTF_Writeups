import socket,time
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
def H(body,chk,b7=0,b8=0,b10=0,b11=0):
    body=bytes(body);n=len(body)
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([b7,b8,chk,b10,b11])+body).hex()
s=conn()
print('known good body[0] chk0:', cmd(s,'load '+H([0],0)))
# count matches for body[0] over all chk
oks=[chk for chk in range(256) if 'checksum' not in cmd(s,'load '+H([0],chk))]
print('body[0] matching chks:',[hex(x) for x in oks])
# now prog
prog=[0x10,0x41,0x27]
oks2=[chk for chk in range(256) if 'checksum' not in cmd(s,'load '+H(prog,chk))]
print('prog matching chks:',[hex(x) for x in oks2])
s.close()

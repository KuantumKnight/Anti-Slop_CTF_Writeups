import socket, time
def chat(cmds):
    s=socket.socket(); s.connect(('178.105.199.41',20006)); time.sleep(0.4)
    s.settimeout(1.5);
    def rd():
        b=b''
        try:
            while True: b+=s.recv(4096)
        except: pass
        return b.decode(errors='replace')
    rd()
    res=[]
    for c in cmds:
        s.sendall((c+'\n').encode()); time.sleep(0.35); res.append(rd())
    s.close(); return res
# same epoch multiple times in one session and across sessions
out=chat(['diag 5','diag 5','diag 5'])
for o in out: print(o.strip())

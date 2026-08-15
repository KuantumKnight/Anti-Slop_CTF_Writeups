import socket, time
def conn():
    s=socket.socket(); s.connect(('178.105.199.41',20006)); return s
def rl(s,t=3.0):
    s.settimeout(t); out=b''
    try:
        while True:
            d=s.recv(4096)
            if not d: break
            out+=d
            if out.endswith(b'\n') and time.time():
                # peek a bit more
                pass
    except: pass
    return out
def chat(cmds):
    s=conn(); time.sleep(0.4)
    s.settimeout(1.5); buf=b''
    try:
        while True: buf+=s.recv(4096)
    except: pass
    print("BANNER:",buf.decode(errors='replace'))
    for c in cmds:
        s.sendall((c+'\n').encode()); time.sleep(0.5)
        b=b''
        s.settimeout(1.5)
        try:
            while True: b+=s.recv(4096)
        except: pass
        print(f">>> {c}\n{b.decode(errors='replace')}")
    s.close()
chat(['diag 0','diag 1','diag 2','diag 100'])

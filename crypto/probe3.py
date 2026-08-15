import socket, time
def chat(cmds):
    s=socket.socket(); s.connect(('178.105.199.41',20006)); time.sleep(0.4); s.settimeout(1.5)
    def rd():
        b=b''
        try:
            while True: b+=s.recv(4096)
        except: pass
        return b.decode(errors='replace')
    print("BANNER:",rd().strip())
    for c in cmds:
        s.sendall((c+'\n').encode()); time.sleep(0.35)
        print(f">>> {c}\n{rd().strip()}")
    s.close()
# explore: dryrun/commit without load, auth with junk, simple load
chat(['dryrun','commit','auth 00','auth '+ '00'*64, 'load 00','dryrun','load deadbeef','dryrun','commit','info'])

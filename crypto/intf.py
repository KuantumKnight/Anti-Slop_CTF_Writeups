import socket, time, sys
class S:
    def __init__(self):
        self.s=socket.socket(); self.s.connect(('178.105.199.41',20006)); time.sleep(0.4); self.s.settimeout(1.2)
        self.banner=self.rd()
    def rd(self):
        b=b''
        try:
            while True:
                d=self.s.recv(4096)
                if not d: break
                b+=d
        except: pass
        return b.decode(errors='replace')
    def cmd(self,c):
        self.s.sendall((c+'\n').encode()); time.sleep(0.3); return self.rd()
if __name__=='__main__':
    s=S()
    # try various capsule loads to learn format. header: magic PDFT, ver 02, len u16 LE, +5 bytes, body
    tests=[
        '50444654',                 # just magic
        '5044465402'+'0000',        # magic ver len=0 (10 bytes -> short? need >=12)
        '5044465402'+'0000'+'0000000000',  # 12 bytes, len=0 body empty
        '5044465402'+'0100'+'0000000000'+'ff',   # len=1 body=ff
        '5044465402'+'0100'+'0000000000'+'00',
        '5044465402'+'0200'+'0000000000'+'0000',
    ]
    for t in tests:
        print(f"LOAD {t} ({len(t)//2}B):", s.cmd('load '+t).strip())

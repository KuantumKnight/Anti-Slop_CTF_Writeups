import socket, time, re, json
def session():
    s=socket.socket(); s.connect(('178.105.199.41',20006)); time.sleep(0.4)
    s.settimeout(1.2)
    def rd():
        b=b''
        try:
            while True: b+=s.recv(4096)
        except: pass
        return b.decode(errors='replace')
    rd()
    return s, rd
def diag(rd,s,e):
    s.sendall(f'diag {e}\n'.encode()); time.sleep(0.3); return rd()
s,rd=session()
data={}
for e in range(0,24):
    out=diag(rd,s,e)
    m=re.search(r'epoch=(\d+) digest=([0-9a-f]+) sig=([0-9a-f]+)',out)
    if m:
        data[e]={'epoch':int(m.group(1)),'z':m.group(2),'sig':m.group(3)}
s.close()
json.dump(data,open('diag.json','w'),indent=0)
for e in sorted(data):
    d=data[e]; sig=d['sig']
    print(e,'->epoch',d['epoch'],'r',sig[:16],'...','s',sig[64:80],'...')

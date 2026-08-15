from intf import S
def hdr(body,chk,b7=0,b8=0,b10=0,b11=0):
    body=bytes(body); n=len(body)
    return (b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([b7,b8,chk,b10,b11])+body).hex()
s=S()
prog=[0x10,0x41,0x27]   # push8 0x41 ; emit
for chk in range(256):
    r=s.cmd('load '+hdr(prog,chk))
    if 'checksum' not in r:
        print(f'chk=0x{chk:02x}:',r.strip());
        if 'ok' in r:
            print('dryrun:', s.cmd('dryrun').strip())
            print('commit:', s.cmd('commit').strip())
            print('commit2:', s.cmd('commit').strip())
            print('info:', s.cmd('info').strip())
            break

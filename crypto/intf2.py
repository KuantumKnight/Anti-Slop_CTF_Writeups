from intf import S
import time
def mk(body, b7=0,b8=0,chk=None,b10=0,b11=0):
    body=bytes(body)
    n=len(body)
    if chk is None: chk=sum(body)&0xff
    hdr=b'PDFT'+bytes([2])+n.to_bytes(2,'little')+bytes([b7,b8,chk,b10,b11])
    return (hdr+body).hex()
s=S()
# verify checksum = sum mod 256
print('body=ff sum-chk:', s.cmd('load '+mk([0xff])).strip())
print('body=01 02 sum-chk:', s.cmd('load '+mk([1,2])).strip())
# load a working one and run lifecycle
print('load 00:', s.cmd('load '+mk([0])).strip())
print('dryrun:', s.cmd('dryrun').strip())
print('commit:', s.cmd('commit').strip())
print('info:', s.cmd('info').strip())
print('commit2:', s.cmd('commit').strip())

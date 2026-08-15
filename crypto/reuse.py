import re
from poly import conn, cmd, asm
prog=[0x10,1,0x10,2,0x10,3,0x10,4,0x40]
def first_commit():
    s,b=conn(); sid=re.search(r'sid=(\d+)',b).group(1)
    cmd(s,'load '+asm(prog)); cmd(s,'dryrun')
    r=cmd(s,'commit'); s.close()
    m=re.search(r'preview=([0-9a-f]+) digest=([0-9a-f]+) sig=([0-9a-f]+)',r)
    return sid,m.group(1),m.group(2),m.group(3)
res=[first_commit() for _ in range(4)]
for sid,prev,dig,sig in res:
    print(f'sid={sid} preview={prev} digest={dig[:20]} r={sig[:24]}')
rs=set(x[3][:64] for x in res)
print('distinct r across sessions:',len(rs),'/',len(res))
print('distinct digest:',len(set(x[2] for x in res)))

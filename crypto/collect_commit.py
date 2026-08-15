import re, json
from poly import conn, cmd, asm
s,b=conn()
sid=int(re.search(r'sid=(\d+)',b).group(1))
prog=[0x10,1,0x10,2,0x10,3,0x10,4,0x40]
rows=[]
for i in range(16):
    cmd(s,'load '+asm(prog))
    cmd(s,'dryrun')
    r=cmd(s,'commit')
    m=re.search(r'epoch=(\d+) preview=([0-9a-f]+) digest=([0-9a-f]+) sig=([0-9a-f]+)',r)
    inf=cmd(s,'info')
    cm=re.search(r'commits=(\d+)',inf)
    if m:
        rows.append({'commit':int(cm.group(1)),'epoch':int(m.group(1)),'digest':m.group(3),'sig':m.group(4)})
json.dump({'sid':sid,'rows':rows},open('commit.json','w'))
for x in rows: print(x['commit'],'epoch',x['epoch'],'r',x['sig'][:12])
s.close()

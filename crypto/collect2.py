import re, json
from poly import conn, cmd, asm
s,b=conn()
rows=[]
# vary the pushed values -> different previews/digests
for a in range(1,9):
  for bb in range(1,6):
    prog=[0x10,a,0x10,bb,0x10,3,0x10,4,0x40]
    cmd(s,'load '+asm(prog)); cmd(s,'dryrun')
    r=cmd(s,'commit')
    m=re.search(r'epoch=(\d+) preview=([0-9a-f]+) digest=([0-9a-f]+) sig=([0-9a-f]+)',r)
    if m: rows.append({'a':a,'b':bb,'epoch':int(m.group(1)),'preview':m.group(2),'digest':m.group(3),'sig':m.group(4)})
json.dump(rows,open('commit2.json','w'))
rs=[x['sig'][:64] for x in rows]
print('total',len(rows),'unique r',len(set(rs)))
# epochs distribution
from collections import Counter
print('epochs',Counter(x['epoch'] for x in rows))
print('previews sample',[(x['preview'],x['epoch']) for x in rows[:8]])
s.close()

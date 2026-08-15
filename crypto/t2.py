from poly import conn,cmd,asm
s,b=conn()
progs=[
 ([0x10,1,0x10,2,0x10,3,0x10,4,0x40],'push 1..4; emit'),
 ([0x10,1,0x10,2,0x10,3,0x10,4,0x40,0x00],'..emit; end'),
]
for ops,desc in progs:
    print(desc)
    print('  load:',cmd(s,'load '+asm(ops)))
    print('  dryrun:',cmd(s,'dryrun'))
    print('  commit:',cmd(s,'commit'))
    print('  info:',cmd(s,'info'))
s.close()

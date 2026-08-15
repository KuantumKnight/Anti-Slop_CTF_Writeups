from poly import conn,cmd,asm
s,b=conn()
for ops,desc in [
  ([0x10,0x42,0x27],'push8 0x42; emit'),
  ([0x10,0x42,0x10,0x43,0x27],'push8;push8;emit'),
  ([0x10,0x42],'push8 only'),
  ([0x27],'emit empty'),
  ([0x10,0x42,0x24,0x27],'push8;dup;emit'),
]:
    print(desc,'load:',cmd(s,'load '+asm(ops)),'| dry:',cmd(s,'dryrun'),'| commit:',cmd(s,'commit'))
s.close()

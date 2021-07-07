from pwn import *
import ast
from z3 import *
r = remote("pwnable.kr", 9016)

def f(p):
	board = []
	rowCol = []
	r.sendline()
	sleep(0.1)
	r.recvuntil("Stage " + str(p) + "\n")
	sleep(0.1)
	r.recvuntil("\n")
	sleep(0.1)
	for i in range(9):
		board.append(ast.literal_eval(str(r.recvline())[2:].split("\\n'")[0]))
	zeros = [(i, j) for i in range(9) for j in range(9) if board[i][j] == 0]
	r.recvuntil(b"- additional rule -")
	r.recvline()
	
	num = str(r.recvline()).split("than ")[1].replace("\\n'", "")
	bigger = int(num.lstrip())
	data = (str(r.recvuntil("s")[2:]).split("(row,col) : "))
	del(data[0])
	for i in range(len(data)):
		data[i] = data[i].split("\n")[0]
	for i in range(len(data)):
		dataSplit = data[i].split(',')
		row = dataSplit[0].replace("(", "").replace("\\n","")
		col = dataSplit[1].replace(")", "").replace("\\n","")
		col = col.replace("s","")
		col = col.replace("'", "")
		rowCol.append([int(row), int(col)])
	r.info("bigger than number : " + str(num))
	print(board)
	print(rowCol)
	sen = []
	while True:
		ans = [[Int("ans_{}{}".format(i, j)) for j in range(9)] for i in range(9)]
		solver = Solver()
		for i in range(9):
			for j in range(9):
				if board[i][j]:
					solver.add(ans[i][j] == board[i][j])
				solver.add(And(1 <= ans[i][j], ans[i][j] <= 9))

		for i in range(9):
			solver.add(Distinct([ans[i][j] for j in range(9)]) )
			solver.add(Distinct([ans[j][i] for j in range(9)]) )
			solver.add(Distinct([ans[3 * (i // 3) + j1][3 * (i % 3) + j2] for j1 in range(3) for j2 in range(3)]))
		if solver.check() == sat:
			model = solver.model()
			res = 0
			for i in range(9):
				for j in range(9):
					res += (model[ans[i][j]].as_long())
			if (res > bigger):
				for i in range(9):
					s = ""
					l = []
					for j in range(9):
						s += "{} ".format(model[ans[i][j]].as_long())
						l.append(model[ans[i][j]].as_long())
					#print(s)
					sen.append(l)
				print(sen)
				break
		else:
			continue
	sen = str(sen).replace(" ", "")
	sleep(0.2)
	r.sendline(sen)
	sleep(1)
	r.interactive()
if __name__ == "__main__":
	r.recvuntil("press enter to see example.")
	sleep(0.1)
	r.sendline()
	r.recvuntil("press enter to start game")
	sleep(0.1)
	for i in range(1, 101):
		f(i)
		

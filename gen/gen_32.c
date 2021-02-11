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
#include "bpf32"
	//prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	//prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
	register void *eax asm("eax");
	register void *ebx asm("ebx");
	register void *ecx asm("ecx");
	register void *edx asm("edx");
	register void *esi asm("esi");
	register void *edi asm("edi");
	eax = (void *)SYS_prctl;
	ebx = (void *)PR_SET_NO_NEW_PRIVS;
	ecx = (void *)1;
	edx = (void *)0;
	esi = (void *)0;
	edi = (void *)0;
	__asm__("int $0x80");
	eax = (void *)SYS_prctl;
	ebx = (void *)PR_SET_SECCOMP;
	ecx = (void *)SECCOMP_MODE_FILTER;
	edx = (void *)&sfp;
	__asm__("int $0x80");
}

int main()
{
	seccomp();
	return 0;
}
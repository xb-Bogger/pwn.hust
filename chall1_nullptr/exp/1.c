#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

struct null_t {
    struct null_item_t *item;
};

struct null_item_t {
    uint32_t foo;
    void (*callback)(void);
    char bar[1];
};

static struct null_t null; /* initialized by zeros */

int main(void)
{
    int ret = EXIT_FAILURE;

    /* Fill all the operations in the kernel module */
    int fd = open("/dev/null_act", O_WRONLY);
    if (fd == -1) {
        perror("open");
        goto out;
    }

    // NULL_ACT_ALLOC
    ioctl(fd, 0x40001);

    // Allocate memory for null.item
    null.item = malloc(sizeof(struct null_item_t));
    if (null.item == NULL) {
        perror("malloc");
        goto close_fd;
    }

    // NULL_ACT_CALLBACK
    if (ioctl(fd, 0x40002, &null.item) == -1) {
        perror("ioctl NULL_ACT_CALLBACK");
        goto free_memory;
    }

    // NULL_ACT_FREE
    ioctl(fd, 0x40003);

    // NULL_ACT_RESET
    ioctl(fd, 0x40004);

    ret = EXIT_SUCCESS;

free_memory:
    free(null.item);
close_fd:
    close(fd);
out:
    return ret;
}
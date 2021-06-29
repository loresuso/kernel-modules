#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lorenzo Susini");

/* System call target RIP on syscall instruction */
#define IA32_LSTAR 0xc0000082

unsigned long long x86_get_msr(int msr)
{
    unsigned long msrl = 0, msrh = 0;

    /*
    *   rdmsr operation:
    *   EDX:EAX := MSR[ECX];
    */
    asm volatile("rdmsr"
                 : "=a"(msrl), "=d"(msrh)
                 : "c"(msr));

    return ((unsigned long long)msrh << 32) | msrl;
}

static int __init msr_test_init(void)
{
    unsigned long long result;
    const unsigned int msr = IA32_LSTAR;
    unsigned long *bitmap;
    printk(KERN_INFO "-----------------------------------\n");
    printk(KERN_INFO "|           MSR test              |\n");
    printk(KERN_INFO "-----------------------------------\n");

    result = x86_get_msr(msr);
    printk(KERN_INFO "Read Msr:\t%#x\n", msr);
    printk(KERN_INFO "Result:\t%#llx\n", result);

    printk(KERN_INFO "----------------------------------\n");
    bitmap = bitmap_zalloc(2050000, GFP_KERNEL);
    bitmap_set(bitmap, 6, 1);
    bitmap_free(bitmap);
    printk("0x%lx", *bitmap);
    printk(KERN_INFO "----------------------------------\n");
    return 0;
}
static void __exit msr_test_exit(void)
{
    printk(KERN_INFO "Unload msr_test.\n");
}

module_init(msr_test_init);
module_exit(msr_test_exit);

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("GPL");

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


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <asm/desc.h>
#include <linux/irq.h>
#include <linux/interrupt.h> 

#include "double-kprobe.h"
#include "read-msr.h"

int (*set_memory_pointer)(unsigned long, int);
int (*reset_memory_pointer)(unsigned long, int);

struct irq_desc *(*i2d_pointer)(int irq) = NULL; /* irq_to_desc function pointer */
struct irqaction *keyboard_action;
void *irq_handler_code;

irqreturn_t (*old_handler)(int irq, void *dev) = NULL;
static irqreturn_t hook_handler(int irq, void *dev){
    printk("Hooked myself ERROR!!!\n");
    return old_handler(irq, dev);
}

static void disable_cr0_wp(void)
{
    asm __volatile__ (
        "cli;"
        "mov %cr0, %eax"
        "and $~0x10000, %eax"
        "mov %eax, %cr0"
        "sti"
        ::
    );
}

static void enable_cr0_wp(void)
{
    asm __volatile__ (
        "cli;"
        "mov %cr0, %eax"
        "or $0x10000, %eax"
        "mov %eax, %cr0"
        "sti"
        ::
    );
}

static void walk_irqactions(int irq)
{
    struct irq_desc *desc;
    struct irqaction *action, **action_ptr;

    desc = i2d_pointer(irq);
    if(desc == NULL)
        return;
    action_ptr = &desc->action;       
    if(action_ptr != NULL)                                       
        action = *action_ptr; 
    else
        action = NULL;
    while(action != NULL){
        if(!strcmp("fx_irq_handler", action->name)){
            irq_handler_code = (void *)action->handler;
            old_handler = action->handler;
            action->handler = hook_handler;
        }
        action = action->next;
    }
}

static void init_set_memory_functions(void)
{
    set_memory_pointer = (int (*)(unsigned long, int))kln_pointer("set_memory_rw");
    reset_memory_pointer = (int (*)(unsigned long, int))kln_pointer("set_memory_ro");
}

static void idt_attack_test(struct desc_ptr *descriptor)
{
    char *ptr;

    set_memory_pointer(descriptor->address, 1);
    ptr = (char *)descriptor->address;
    *(ptr + 5) = 6;
    reset_memory_pointer(descriptor->address, 1);
    return;
}


static void attack_irq_desc(void)
{
    void *irqdesc = (void *)i2d_pointer(11);
    memset(irqdesc, 0, sizeof(struct irq_desc));
}


static int m_init(void)
{
    int ret, i;
    struct desc_ptr *idt_ptr;

    pr_info("module loaded\n");

    printk("Syscall MSR register value: %llx", x86_get_msr(IA32_LSTAR));

    ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
    if (ret < 0)
        return ret;

    ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
    if (ret < 0) {
        unregister_kprobe(&kp0);
        return ret;
    }

    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);  
    kln_pointer = (unsigned long (*)(const char *name)) kln_addr;

    i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));
    for(i = 0; i < 256; i++)
        walk_irqactions(i);

    init_set_memory_functions();
    idt_ptr = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(idt_ptr);
    printk("Writing IDT\n");
    //idt_attack_test(idt_ptr);
    kfree(idt_ptr);

    //attack_irq_desc();

    return 0;
}

static void m_exit(void)
{
  //keyboard_action->handler = old_keyboard;
  pr_info("module unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");


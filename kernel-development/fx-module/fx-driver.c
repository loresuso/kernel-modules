#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <asm/desc.h>
#include <linux/irq.h>
#include <linux/interrupt.h> 
#include <linux/kprobes.h>

MODULE_AUTHOR("Lorenzo Susini");
MODULE_LICENSE("GPL");

/*
*    PCI constants
*/
#define VENDOR_ID   0x1234
#define DEVICE_ID   0x0609
#define BAR         0

#define ID_REGISTER                 0x00
#define CARD_LIVENESS_REGISTER      0x04
#define ADDR_REGISTER               0x08
#define INTERRUPT_STATUS_REGISTER   0x24
#define INTERRUPT_RAISE_REGISTER    0x60
#define INTERRUPT_ACK_REGISTER      0x64
#define PROTECT_IDT_COMMAND         0x80

/*
*    Kprobes, for accessing all kernel code
*/
#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)
long unsigned kln_addr = 0; /* kallsym_loop_name address*/
unsigned long (*kln_pointer)(const char* name); /* kallsym_loop_name function pointer */
struct irq_desc *(*i2d_pointer)(int irq); /* irq_to_desc function pointer */

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
  
  /*pr_info("Planted kprobe for symbol %s at %px\n", symbol_name, kp->addr);*/
  return ret;
}

/*   
*   Interrupt handling variables
*/
static struct pci_dev *pdev; /* PCI device */
static void __iomem *mmio; /* memory mapped I/O */
static int pci_irq;
static struct irq_desc *irq_desc_pci;
static struct irqaction *irqaction_pci;

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);


static irqreturn_t irq_handler(int irq, void *dev)
{
    u32 irq_status;
    printk("Got an interrupt");
    /* ack the interrupt */
    irq_status = ioread32(mmio + INTERRUPT_STATUS_REGISTER);
    iowrite32(irq_status, mmio + INTERRUPT_ACK_REGISTER);
    /* write the address of where kvm has to put the code */
    iowrite32(0xAAAAAAAA, mmio + ADDR_REGISTER);
    return IRQ_HANDLED;
}


static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    u8 val;
    pdev = dev;
    if(pci_enable_device(pdev) < 0){
        dev_err(&(pdev->dev), "error in pci_enable_device\n");
        return -1;
    }
    if(pci_request_region(pdev, BAR, "myregion0")){
		dev_err(&(pdev->dev), "error in pci_request_region\n");
		return -1;
	}
    mmio = pci_iomap(pdev, BAR, pci_resource_len(pdev, BAR));

	/* IRQ setup */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &val);
	pci_irq = val;
	if (request_irq(pci_irq, irq_handler, 0, "fx_irq_handler", NULL) < 0) {
		dev_err(&(dev->dev), "request_irq\n");
		return -1;
	}
    return 0;
}


static void pci_remove(struct pci_dev *dev)
{
	pr_info("pci_remove\n");
    pci_release_region(dev, BAR);
}


static struct pci_driver pci_driver = { 
    .name = "fx_pci",
    .id_table = pci_ids, 
    .probe = pci_probe, 
    .remove = pci_remove,
};

static void protect_idt_hypercall(void)
{
   /*  
   *   putting parameters into registers,
   *   then triggering the vmexit
   */
    __asm__ volatile("movq %0, %%r8" ::"r"(THIS_MODULE->core_layout.base));
    __asm__ volatile("mov %0, %%r9" ::"r"(&(irq_desc_pci->action))); /* address of the head of the list of irqaction */
    __asm__ volatile("mov %0, %%r10" ::"r"(irqaction_pci)); /* the irq action pointing to the handler */
    __asm__ volatile("mov %0, %%r11" ::"r"(sizeof(struct irqaction)));
    __asm__ volatile("mov %0, %%r12" ::"r"(sizeof(struct irq_desc)));
    __asm__ volatile("mov %0, %%rax" ::"r"(mmio + PROTECT_IDT_COMMAND));
    __asm__ volatile("movq $1, (%%rax)"::); /* triggering the hypercall */
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
        printk("IRQ: %d, Action name: %s, address: %px\n", action->irq, (action->name == NULL) ? "no name":action->name, (void *)action);
        if(!strcmp("fx_irq_handler", action->name)){
            /* important: set parameters for hypercall */
            irq_desc_pci = desc;
            irqaction_pci = action;
            break;
        }
        action = action->next;
    }
}

static void show_module_base_and_size(void)
{
    printk("Module base address: %px, Size: 0x%x\n", THIS_MODULE->core_layout.base, THIS_MODULE->core_layout.size);
}

static void hide_module(void)
{
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
}


static int m1_init(void)
{
    int ret;
    struct desc_ptr *descriptor = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(descriptor);
    printk("FX - Forced eXecution module started \n");
    printk("IDT address is 0x%lx, size %d", descriptor->address, (int)descriptor->size);
    pr_info("irq_handler address %px\n", irq_handler);

    /* double kprobe technique */
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

    if(pci_register_driver(&pci_driver) < 0){
        printk("Cannot register PCI driver");
        return 1;
    }

    walk_irqactions(pci_irq);
    protect_idt_hypercall();

    kfree(descriptor);
    descriptor = NULL;

    show_module_base_and_size();
    hide_module();
    return 0;
}


static void m1_exit(void)
{
    pci_unregister_driver(&pci_driver);
    printk("FX - Forced eXecution module removed \n");
}

module_init(m1_init);
module_exit(m1_exit);
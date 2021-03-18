#include <linux/module.h>
#include <linux/pci.h>
#include <asm/desc.h>

/*
*    PCI constants
*/
#define VENDOR_ID 0x1234
#define DEVICE_ID 0x0609
#define BAR 0

#define ID_REGISTER                 0x00
#define CARD_LIVENESS_REGISTER      0x04
#define ADDR_REGISTER               0x08
#define INTERRUPT_STATUS_REGISTER   0x24
#define INTERRUPT_RAISE_REGISTER    0x60
#define INTERRUPT_ACK_REGISTER      0x64
#define PROTECT_IDT_COMMAND         0x80

MODULE_AUTHOR("Lorenzo Susini");
MODULE_LICENSE("Dual BSD/GPL");

static struct pci_dev *pdev; /* PCI device */
static void __iomem *mmio; /* memory mapped I/O */
static int pci_irq;

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static irqreturn_t irq_handler(int irq, void *dev){
    u32 irq_status;
    printk("Got an interrupt");
    /* ack the interrupt */
    irq_status = ioread32(mmio + INTERRUPT_STATUS_REGISTER);
    iowrite32(irq_status, mmio + INTERRUPT_ACK_REGISTER);
    /* write the address of where kvm has to put the code */
    iowrite32(0xAAAAAAAA, mmio + ADDR_REGISTER);
    return IRQ_HANDLED;
}

static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id){
    u8 val;
    u32 device_version;
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
    /* Protect IDT command */
    iowrite32(0x1, mmio + PROTECT_IDT_COMMAND);
    /* Checks */
    device_version = ioread32(mmio + ID_REGISTER);
    printk("Device version ID: 0x%x", device_version);

    return 0;
}

static void pci_remove(struct pci_dev *dev){
	pr_info("pci_remove\n");
    pci_release_region(dev, BAR);
}

static struct pci_driver pci_driver = { 
    .name = "fx_pci",
    .id_table = pci_ids, 
    .probe = pci_probe, 
    .remove = pci_remove,
};

static int m1_init(void) {
    struct desc_ptr *descriptor = kmalloc(sizeof(struct desc_ptr), GFP_KERNEL);
    store_idt(descriptor);
    printk("FX - Force eXecution started \n");
    printk("IDT address is 0x%lx", descriptor->address);
    printk("irq_handler_address: %p", irq_handler);
    kfree(descriptor);
    if(pci_register_driver(&pci_driver) < 0){
        printk("Cannot register PCI driver");
        return 1;
    }
    return 0;
}

static void m1_exit(void) {
    //pci_unregister_driver(&pci_driver);
    printk("FX - Force eXecution removed \n");
}

module_init(m1_init);
module_exit(m1_exit);
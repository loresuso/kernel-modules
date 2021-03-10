#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

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
    /* Ack the interrupt */
    irq_status = ioread32(mmio + INTERRUPT_STATUS_REGISTER);
    iowrite32(irq_status, mmio + INTERRUPT_ACK_REGISTER);
    iowrite32(0xAAAAAAAA, mmio + ADDR_REGISTER);
    return IRQ_HANDLED;
}

/*  This probing function gets called (during execution of pci_register_driver() 
*   for already existing devices or later if a new device gets inserted) for all
*   PCI devices which match the ID table and are not “owned” by the other drivers yet.
*   This function gets passed a “struct pci_dev *” for each device whose entry in the 
*   ID table matches the device. The probe function returns zero when the driver 
*   chooses to take “ownership” of the device or an error code (negative number) otherwise.
*   The probe function always gets called from process context, so it can sleep.
*/
static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id){
    u8 val;
    u32 device_version;
    u32 card_liveness;
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

    /* Checks */
    device_version = ioread32(mmio + ID_REGISTER);
    printk("Device version ID: 0x%x", device_version);
    iowrite32(0x123, mmio + CARD_LIVENESS_REGISTER);
    card_liveness = ioread32(mmio + CARD_LIVENESS_REGISTER);
    printk("Card Liveness (must be 0xff...ff): %d", 0x123 + card_liveness);

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
    printk("FX - Force eXecution started \n");
    if(pci_register_driver(&pci_driver) < 0){
        printk("Cannot register PCI driver");
        return 1;
    }
    printk("PCI driver registered succesfully");
    return 0;
}

static void m1_exit(void) {
    pci_unregister_driver(&pci_driver);
    printk("FX - Force eXecution removed \n");
}

module_init(m1_init);
module_exit(m1_exit);
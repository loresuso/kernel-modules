#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>

/**************************
*    PCI constants
***************************/
#define VENDOR_ID 0x1234
#define DEVICE_ID 0x11e8

MODULE_AUTHOR("Lorenzo Susini");
MODULE_LICENSE("Dual BSD/GPL");

static struct pci_dev *pdev;

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VENDOR_ID, DEVICE_ID), },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

/*  This probing function gets called (during execution of pci_register_driver() 
*   for already existing devices or later if a new device gets inserted) for all
*   PCI devices which match the ID table and are not “owned” by the other drivers yet.
*   This function gets passed a “struct pci_dev *” for each device whose entry in the 
*   ID table matches the device. The probe function returns zero when the driver 
*   chooses to take “ownership” of the device or an error code (negative number) otherwise.
*   The probe function always gets called from process context, so it can sleep.
*/
static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id){
	pr_info("pci_probe\n");
    printk("Vendor: 0x%x, Device: 0x%x\n", dev->vendor, dev->device);
    return 0;
}

static void pci_remove(struct pci_dev *dev){
	pr_info("pci_remove\n");
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
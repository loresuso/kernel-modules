/*
 * QEMU Force eXecution PCI device
 * 2021 Lorenzo Susini
*/

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"

#define TYPE_PCI_FXPCI_DEVICE "fx"
typedef struct FxState FxState;
DECLARE_INSTANCE_CHECKER(FxState, FX,
                         TYPE_PCI_FXPCI_DEVICE)

#define ID_REGISTER         0x00
#define ADDR_REGISTER       0x08

struct FxState {
    PCIDevice pdev;
    MemoryRegion mmio;

    QemuThread thread;
    QemuMutex thr_mutex;
    /* thread must raise an interrupt and wait for 
        the address back from guest*/
    QemuCond thr_cond; 
    bool stopping;

    uint32_t pending_irq;
    uint64_t addr;
};

static bool fx_msi_enabled(FxState *);
static void fx_raise_irq(FxState *);
static void fx_lower_irq(FxState *);
static uint64_t fx_mmio_read(void *, hwaddr, unsigned);
static void fx_mmio_write(void *, hwaddr, uint64_t, unsigned);
static void *fx_forcer_thread(void *);
static void pci_fx_realize(PCIDevice *, Error **);
static void pci_fx_uninit(PCIDevice *);
static void fx_instance_init(Object *);
static void fx_class_init(ObjectClass *, void *);
static void pci_fx_register_types(void);

static const MemoryRegionOps fx_mmio_ops = {
    .read = fx_mmio_read,
    .write = fx_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static bool fx_msi_enabled(FxState *fx)
{
    return msi_enabled(&fx->pdev);
}

static void fx_raise_irq(FxState *fx)
{
    if (fx_msi_enabled(fx)) {
        msi_notify(&fx->pdev, 0);
    } else {
        pci_set_irq(&fx->pdev, 1);
    }
}

static void fx_lower_irq(FxState *fx)
{
    if (!fx_msi_enabled(fx)) {
        pci_set_irq(&fx->pdev, 0);
    }
}

static uint64_t fx_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    //FxState *fx = opaque;
    uint64_t val = ~0ULL;

    if(size != 8)
        return val;

    switch (addr) {
        case ID_REGISTER:
            val = 0x010000edu;
            break;
        default:
            break;
        }

    return val;
}

static void fx_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    FxState *fx = opaque;

    if(size != 8)
        return;

    switch (addr) {
    case ADDR_REGISTER:
        qemu_mutex_lock(&fx->thr_mutex);
        fx->pending_irq = 0;
        fx->addr = val;
        fx_lower_irq(fx);
        qemu_cond_signal(&fx->thr_cond);
        qemu_mutex_unlock(&fx->thr_mutex);
        break;
    default:
        break;
    }
}

static void *fx_forcer_thread(void *opaque)
{
    FxState *fx = opaque;

    while (1) {
        uint64_t addr;

        g_usleep(5 * G_USEC_PER_SEC);

        qemu_mutex_lock(&fx->thr_mutex);
        fx_raise_irq(fx);
        fx->pending_irq = 1;
        while((qatomic_read(&fx->pending_irq) == 1)){
            qemu_cond_wait(&fx->thr_cond, &fx->thr_mutex);
        }

        if(fx->stopping){
            qemu_mutex_unlock(&fx->thr_mutex);
            break;
        }

        addr = fx->addr;

        qemu_mutex_unlock(&fx->thr_mutex);

        /*
        *   DO THE KVM STUFF HERE
        */ 
        fprintf(stderr, "forcer thread restart its actions, addr = 0x%lx", addr);

    }

    return NULL;
}

static void pci_fx_realize(PCIDevice *pdev, Error **errp)
{
    FxState *fx = FX(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    qemu_mutex_init(&fx->thr_mutex);
    qemu_cond_init(&fx->thr_cond);
    qemu_thread_create(&fx->thread, "fx", fx_forcer_thread,
                       fx, QEMU_THREAD_JOINABLE);

    memory_region_init_io(&fx->mmio, OBJECT(fx), &fx_mmio_ops, fx,
                    "fx-mmio", 1 * MiB);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &fx->mmio);
}

static void pci_fx_uninit(PCIDevice *pdev)
{
    FxState *fx = FX(pdev);

    qemu_mutex_lock(&fx->thr_mutex);
    fx->stopping = true;
    qemu_mutex_unlock(&fx->thr_mutex);
    qemu_cond_signal(&fx->thr_cond);
    qemu_thread_join(&fx->thread);

    qemu_cond_destroy(&fx->thr_cond);
    qemu_mutex_destroy(&fx->thr_mutex);

    msi_uninit(pdev);
}

static void fx_instance_init(Object *obj)
{
    FxState *fx = FX(obj);

    fx->pending_irq = 0;
    fx->addr = 0ULL;
}

static void fx_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_fx_realize;
    k->exit = pci_fx_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11ff;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void pci_fx_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo fx_info = {
        .name          = TYPE_PCI_FXPCI_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(FxState),
        .instance_init = fx_instance_init,
        .class_init    = fx_class_init,
        .interfaces    = interfaces,
    };

    type_register_static(&fx_info);
}
type_init(pci_fx_register_types)

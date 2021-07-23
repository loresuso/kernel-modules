#include <linux/kprobes.h>
MODULE_LICENSE("GPL");

#define KPROBE_PRE_HANDLER(fname) \
    int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

struct kprobe kp0, kp1;

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
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

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (--regs->ip);
  
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  return 0;
}

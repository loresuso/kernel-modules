#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

int list_proc_init(void) 
{
    struct task_struct *task;
    printk("Process listing: \n");
    for_each_process(task) {
        printk("%s [%d]\n", task->comm, task->pid);
    }
    return 0;
}

void list_proc_exit(void) 
{
    printk("Process listing module removed \n");
}

module_init(list_proc_init);
module_exit(list_proc_exit);

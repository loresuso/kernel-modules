/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_SOFTMMU_GENERATED_TRACERS_H
#define TRACE_SOFTMMU_GENERATED_TRACERS_H

#include "trace/control.h"

extern TraceEvent _TRACE_BALLOON_EVENT_EVENT;
extern TraceEvent _TRACE_CPU_IN_EVENT;
extern TraceEvent _TRACE_CPU_OUT_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_OPS_READ_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_OPS_WRITE_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_SUBPAGE_READ_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_SUBPAGE_WRITE_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_RAM_DEVICE_READ_EVENT;
extern TraceEvent _TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_EVENT;
extern TraceEvent _TRACE_FLATVIEW_NEW_EVENT;
extern TraceEvent _TRACE_FLATVIEW_DESTROY_EVENT;
extern TraceEvent _TRACE_FLATVIEW_DESTROY_RCU_EVENT;
extern TraceEvent _TRACE_VM_STATE_NOTIFY_EVENT;
extern TraceEvent _TRACE_LOAD_FILE_EVENT;
extern TraceEvent _TRACE_RUNSTATE_SET_EVENT;
extern TraceEvent _TRACE_SYSTEM_WAKEUP_REQUEST_EVENT;
extern TraceEvent _TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_EVENT;
extern TraceEvent _TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_EVENT;
extern uint16_t _TRACE_BALLOON_EVENT_DSTATE;
extern uint16_t _TRACE_CPU_IN_DSTATE;
extern uint16_t _TRACE_CPU_OUT_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_OPS_READ_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_OPS_WRITE_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_SUBPAGE_READ_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_SUBPAGE_WRITE_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_RAM_DEVICE_READ_DSTATE;
extern uint16_t _TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_DSTATE;
extern uint16_t _TRACE_FLATVIEW_NEW_DSTATE;
extern uint16_t _TRACE_FLATVIEW_DESTROY_DSTATE;
extern uint16_t _TRACE_FLATVIEW_DESTROY_RCU_DSTATE;
extern uint16_t _TRACE_VM_STATE_NOTIFY_DSTATE;
extern uint16_t _TRACE_LOAD_FILE_DSTATE;
extern uint16_t _TRACE_RUNSTATE_SET_DSTATE;
extern uint16_t _TRACE_SYSTEM_WAKEUP_REQUEST_DSTATE;
extern uint16_t _TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_DSTATE;
extern uint16_t _TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_DSTATE;
#define TRACE_BALLOON_EVENT_ENABLED 1
#define TRACE_CPU_IN_ENABLED 1
#define TRACE_CPU_OUT_ENABLED 1
#define TRACE_MEMORY_REGION_OPS_READ_ENABLED 1
#define TRACE_MEMORY_REGION_OPS_WRITE_ENABLED 1
#define TRACE_MEMORY_REGION_SUBPAGE_READ_ENABLED 1
#define TRACE_MEMORY_REGION_SUBPAGE_WRITE_ENABLED 1
#define TRACE_MEMORY_REGION_RAM_DEVICE_READ_ENABLED 1
#define TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_ENABLED 1
#define TRACE_FLATVIEW_NEW_ENABLED 1
#define TRACE_FLATVIEW_DESTROY_ENABLED 1
#define TRACE_FLATVIEW_DESTROY_RCU_ENABLED 1
#define TRACE_VM_STATE_NOTIFY_ENABLED 1
#define TRACE_LOAD_FILE_ENABLED 1
#define TRACE_RUNSTATE_SET_ENABLED 1
#define TRACE_SYSTEM_WAKEUP_REQUEST_ENABLED 1
#define TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_ENABLED 1
#define TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_ENABLED 1
#include "qemu/log-for-trace.h"
#include "qemu/error-report.h"


#define TRACE_BALLOON_EVENT_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_BALLOON_EVENT) || \
    false)

static inline void _nocheck__trace_balloon_event(void * opaque, unsigned long addr)
{
    if (trace_event_get_state(TRACE_BALLOON_EVENT) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 5 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:balloon_event " "opaque %p addr %lu" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , opaque, addr);
#line 82 "trace/trace-softmmu.h"
        } else {
#line 5 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("balloon_event " "opaque %p addr %lu" "\n", opaque, addr);
#line 86 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_balloon_event(void * opaque, unsigned long addr)
{
    if (true) {
        _nocheck__trace_balloon_event(opaque, addr);
    }
}

#define TRACE_CPU_IN_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_CPU_IN) || \
    false)

static inline void _nocheck__trace_cpu_in(unsigned int addr, char size, unsigned int val)
{
    if (trace_event_get_state(TRACE_CPU_IN) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 8 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:cpu_in " "addr 0x%x(%c) value %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , addr, size, val);
#line 113 "trace/trace-softmmu.h"
        } else {
#line 8 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("cpu_in " "addr 0x%x(%c) value %u" "\n", addr, size, val);
#line 117 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_cpu_in(unsigned int addr, char size, unsigned int val)
{
    if (true) {
        _nocheck__trace_cpu_in(addr, size, val);
    }
}

#define TRACE_CPU_OUT_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_CPU_OUT) || \
    false)

static inline void _nocheck__trace_cpu_out(unsigned int addr, char size, unsigned int val)
{
    if (trace_event_get_state(TRACE_CPU_OUT) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 9 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:cpu_out " "addr 0x%x(%c) value %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , addr, size, val);
#line 144 "trace/trace-softmmu.h"
        } else {
#line 9 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("cpu_out " "addr 0x%x(%c) value %u" "\n", addr, size, val);
#line 148 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_cpu_out(unsigned int addr, char size, unsigned int val)
{
    if (true) {
        _nocheck__trace_cpu_out(addr, size, val);
    }
}

#define TRACE_MEMORY_REGION_OPS_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_OPS_READ) || \
    false)

static inline void _nocheck__trace_memory_region_ops_read(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_OPS_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 12 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_ops_read " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, addr, value, size);
#line 175 "trace/trace-softmmu.h"
        } else {
#line 12 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_ops_read " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, addr, value, size);
#line 179 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_ops_read(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_ops_read(cpu_index, mr, addr, value, size);
    }
}

#define TRACE_MEMORY_REGION_OPS_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_OPS_WRITE) || \
    false)

static inline void _nocheck__trace_memory_region_ops_write(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_OPS_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 13 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_ops_write " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, addr, value, size);
#line 206 "trace/trace-softmmu.h"
        } else {
#line 13 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_ops_write " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, addr, value, size);
#line 210 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_ops_write(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_ops_write(cpu_index, mr, addr, value, size);
    }
}

#define TRACE_MEMORY_REGION_SUBPAGE_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_SUBPAGE_READ) || \
    false)

static inline void _nocheck__trace_memory_region_subpage_read(int cpu_index, void * mr, uint64_t offset, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_SUBPAGE_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 14 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_subpage_read " "cpu %d mr %p offset 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, offset, value, size);
#line 237 "trace/trace-softmmu.h"
        } else {
#line 14 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_subpage_read " "cpu %d mr %p offset 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, offset, value, size);
#line 241 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_subpage_read(int cpu_index, void * mr, uint64_t offset, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_subpage_read(cpu_index, mr, offset, value, size);
    }
}

#define TRACE_MEMORY_REGION_SUBPAGE_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_SUBPAGE_WRITE) || \
    false)

static inline void _nocheck__trace_memory_region_subpage_write(int cpu_index, void * mr, uint64_t offset, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_SUBPAGE_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 15 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_subpage_write " "cpu %d mr %p offset 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, offset, value, size);
#line 268 "trace/trace-softmmu.h"
        } else {
#line 15 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_subpage_write " "cpu %d mr %p offset 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, offset, value, size);
#line 272 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_subpage_write(int cpu_index, void * mr, uint64_t offset, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_subpage_write(cpu_index, mr, offset, value, size);
    }
}

#define TRACE_MEMORY_REGION_RAM_DEVICE_READ_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_RAM_DEVICE_READ) || \
    false)

static inline void _nocheck__trace_memory_region_ram_device_read(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_RAM_DEVICE_READ) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 16 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_ram_device_read " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, addr, value, size);
#line 299 "trace/trace-softmmu.h"
        } else {
#line 16 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_ram_device_read " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, addr, value, size);
#line 303 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_ram_device_read(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_ram_device_read(cpu_index, mr, addr, value, size);
    }
}

#define TRACE_MEMORY_REGION_RAM_DEVICE_WRITE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_MEMORY_REGION_RAM_DEVICE_WRITE) || \
    false)

static inline void _nocheck__trace_memory_region_ram_device_write(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (trace_event_get_state(TRACE_MEMORY_REGION_RAM_DEVICE_WRITE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 17 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:memory_region_ram_device_write " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , cpu_index, mr, addr, value, size);
#line 330 "trace/trace-softmmu.h"
        } else {
#line 17 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("memory_region_ram_device_write " "cpu %d mr %p addr 0x%"PRIx64" value 0x%"PRIx64" size %u" "\n", cpu_index, mr, addr, value, size);
#line 334 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_memory_region_ram_device_write(int cpu_index, void * mr, uint64_t addr, uint64_t value, unsigned size)
{
    if (true) {
        _nocheck__trace_memory_region_ram_device_write(cpu_index, mr, addr, value, size);
    }
}

#define TRACE_FLATVIEW_NEW_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_FLATVIEW_NEW) || \
    false)

static inline void _nocheck__trace_flatview_new(void * view, void * root)
{
    if (trace_event_get_state(TRACE_FLATVIEW_NEW) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 18 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:flatview_new " "%p (root %p)" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , view, root);
#line 361 "trace/trace-softmmu.h"
        } else {
#line 18 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("flatview_new " "%p (root %p)" "\n", view, root);
#line 365 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_flatview_new(void * view, void * root)
{
    if (true) {
        _nocheck__trace_flatview_new(view, root);
    }
}

#define TRACE_FLATVIEW_DESTROY_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_FLATVIEW_DESTROY) || \
    false)

static inline void _nocheck__trace_flatview_destroy(void * view, void * root)
{
    if (trace_event_get_state(TRACE_FLATVIEW_DESTROY) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 19 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:flatview_destroy " "%p (root %p)" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , view, root);
#line 392 "trace/trace-softmmu.h"
        } else {
#line 19 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("flatview_destroy " "%p (root %p)" "\n", view, root);
#line 396 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_flatview_destroy(void * view, void * root)
{
    if (true) {
        _nocheck__trace_flatview_destroy(view, root);
    }
}

#define TRACE_FLATVIEW_DESTROY_RCU_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_FLATVIEW_DESTROY_RCU) || \
    false)

static inline void _nocheck__trace_flatview_destroy_rcu(void * view, void * root)
{
    if (trace_event_get_state(TRACE_FLATVIEW_DESTROY_RCU) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 20 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:flatview_destroy_rcu " "%p (root %p)" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , view, root);
#line 423 "trace/trace-softmmu.h"
        } else {
#line 20 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("flatview_destroy_rcu " "%p (root %p)" "\n", view, root);
#line 427 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_flatview_destroy_rcu(void * view, void * root)
{
    if (true) {
        _nocheck__trace_flatview_destroy_rcu(view, root);
    }
}

#define TRACE_VM_STATE_NOTIFY_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_VM_STATE_NOTIFY) || \
    false)

static inline void _nocheck__trace_vm_state_notify(int running, int reason, const char * reason_str)
{
    if (trace_event_get_state(TRACE_VM_STATE_NOTIFY) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 23 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:vm_state_notify " "running %d reason %d (%s)" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , running, reason, reason_str);
#line 454 "trace/trace-softmmu.h"
        } else {
#line 23 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("vm_state_notify " "running %d reason %d (%s)" "\n", running, reason, reason_str);
#line 458 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_vm_state_notify(int running, int reason, const char * reason_str)
{
    if (true) {
        _nocheck__trace_vm_state_notify(running, reason, reason_str);
    }
}

#define TRACE_LOAD_FILE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_LOAD_FILE) || \
    false)

static inline void _nocheck__trace_load_file(const char * name, const char * path)
{
    if (trace_event_get_state(TRACE_LOAD_FILE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 24 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:load_file " "name %s location %s" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , name, path);
#line 485 "trace/trace-softmmu.h"
        } else {
#line 24 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("load_file " "name %s location %s" "\n", name, path);
#line 489 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_load_file(const char * name, const char * path)
{
    if (true) {
        _nocheck__trace_load_file(name, path);
    }
}

#define TRACE_RUNSTATE_SET_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_RUNSTATE_SET) || \
    false)

static inline void _nocheck__trace_runstate_set(int current_state, const char * current_state_str, int new_state, const char * new_state_str)
{
    if (trace_event_get_state(TRACE_RUNSTATE_SET) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 25 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:runstate_set " "current_run_state %d (%s) new_state %d (%s)" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , current_state, current_state_str, new_state, new_state_str);
#line 516 "trace/trace-softmmu.h"
        } else {
#line 25 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("runstate_set " "current_run_state %d (%s) new_state %d (%s)" "\n", current_state, current_state_str, new_state, new_state_str);
#line 520 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_runstate_set(int current_state, const char * current_state_str, int new_state, const char * new_state_str)
{
    if (true) {
        _nocheck__trace_runstate_set(current_state, current_state_str, new_state, new_state_str);
    }
}

#define TRACE_SYSTEM_WAKEUP_REQUEST_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_SYSTEM_WAKEUP_REQUEST) || \
    false)

static inline void _nocheck__trace_system_wakeup_request(int reason)
{
    if (trace_event_get_state(TRACE_SYSTEM_WAKEUP_REQUEST) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 26 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:system_wakeup_request " "reason=%d" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , reason);
#line 547 "trace/trace-softmmu.h"
        } else {
#line 26 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("system_wakeup_request " "reason=%d" "\n", reason);
#line 551 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_system_wakeup_request(int reason)
{
    if (true) {
        _nocheck__trace_system_wakeup_request(reason);
    }
}

#define TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST) || \
    false)

static inline void _nocheck__trace_qemu_system_shutdown_request(int reason)
{
    if (trace_event_get_state(TRACE_QEMU_SYSTEM_SHUTDOWN_REQUEST) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 27 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:qemu_system_shutdown_request " "reason=%d" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , reason);
#line 578 "trace/trace-softmmu.h"
        } else {
#line 27 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("qemu_system_shutdown_request " "reason=%d" "\n", reason);
#line 582 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_qemu_system_shutdown_request(int reason)
{
    if (true) {
        _nocheck__trace_qemu_system_shutdown_request(reason);
    }
}

#define TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST) || \
    false)

static inline void _nocheck__trace_qemu_system_powerdown_request(void)
{
    if (trace_event_get_state(TRACE_QEMU_SYSTEM_POWERDOWN_REQUEST) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 28 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("%d@%zu.%06zu:qemu_system_powerdown_request " "" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     );
#line 609 "trace/trace-softmmu.h"
        } else {
#line 28 "/home/lore/MasterThesis/qemu/softmmu/trace-events"
            qemu_log("qemu_system_powerdown_request " "" "\n");
#line 613 "trace/trace-softmmu.h"
        }
    }
}

static inline void trace_qemu_system_powerdown_request(void)
{
    if (true) {
        _nocheck__trace_qemu_system_powerdown_request();
    }
}
#endif /* TRACE_SOFTMMU_GENERATED_TRACERS_H */

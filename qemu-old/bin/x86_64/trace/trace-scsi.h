/* This file is autogenerated by tracetool, do not edit. */

#ifndef TRACE_SCSI_GENERATED_TRACERS_H
#define TRACE_SCSI_GENERATED_TRACERS_H

#include "trace/control.h"

extern TraceEvent _TRACE_PR_MANAGER_EXECUTE_EVENT;
extern TraceEvent _TRACE_PR_MANAGER_RUN_EVENT;
extern uint16_t _TRACE_PR_MANAGER_EXECUTE_DSTATE;
extern uint16_t _TRACE_PR_MANAGER_RUN_DSTATE;
#define TRACE_PR_MANAGER_EXECUTE_ENABLED 1
#define TRACE_PR_MANAGER_RUN_ENABLED 1
#include "qemu/log-for-trace.h"
#include "qemu/error-report.h"


#define TRACE_PR_MANAGER_EXECUTE_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_PR_MANAGER_EXECUTE) || \
    false)

static inline void _nocheck__trace_pr_manager_execute(int fd, int cmd, int sa)
{
    if (trace_event_get_state(TRACE_PR_MANAGER_EXECUTE) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 4 "/home/lore/MasterThesis/qemu/scsi/trace-events"
            qemu_log("%d@%zu.%06zu:pr_manager_execute " "fd=%d cmd=0x%02x service action=0x%02x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , fd, cmd, sa);
#line 34 "trace/trace-scsi.h"
        } else {
#line 4 "/home/lore/MasterThesis/qemu/scsi/trace-events"
            qemu_log("pr_manager_execute " "fd=%d cmd=0x%02x service action=0x%02x" "\n", fd, cmd, sa);
#line 38 "trace/trace-scsi.h"
        }
    }
}

static inline void trace_pr_manager_execute(int fd, int cmd, int sa)
{
    if (true) {
        _nocheck__trace_pr_manager_execute(fd, cmd, sa);
    }
}

#define TRACE_PR_MANAGER_RUN_BACKEND_DSTATE() ( \
    trace_event_get_state_dynamic_by_id(TRACE_PR_MANAGER_RUN) || \
    false)

static inline void _nocheck__trace_pr_manager_run(int fd, int cmd, int sa)
{
    if (trace_event_get_state(TRACE_PR_MANAGER_RUN) && qemu_loglevel_mask(LOG_TRACE)) {
        if (message_with_timestamp) {
            struct timeval _now;
            gettimeofday(&_now, NULL);
#line 5 "/home/lore/MasterThesis/qemu/scsi/trace-events"
            qemu_log("%d@%zu.%06zu:pr_manager_run " "fd=%d cmd=0x%02x service action=0x%02x" "\n",
                     qemu_get_thread_id(),
                     (size_t)_now.tv_sec, (size_t)_now.tv_usec
                     , fd, cmd, sa);
#line 65 "trace/trace-scsi.h"
        } else {
#line 5 "/home/lore/MasterThesis/qemu/scsi/trace-events"
            qemu_log("pr_manager_run " "fd=%d cmd=0x%02x service action=0x%02x" "\n", fd, cmd, sa);
#line 69 "trace/trace-scsi.h"
        }
    }
}

static inline void trace_pr_manager_run(int fd, int cmd, int sa)
{
    if (true) {
        _nocheck__trace_pr_manager_run(fd, cmd, sa);
    }
}
#endif /* TRACE_SCSI_GENERATED_TRACERS_H */

/* This file is autogenerated by tracetool, do not edit. */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "trace-qom.h"

uint16_t _TRACE_OBJECT_DYNAMIC_CAST_ASSERT_DSTATE;
uint16_t _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE;
TraceEvent _TRACE_OBJECT_DYNAMIC_CAST_ASSERT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "object_dynamic_cast_assert",
    .sstate = TRACE_OBJECT_DYNAMIC_CAST_ASSERT_ENABLED,
    .dstate = &_TRACE_OBJECT_DYNAMIC_CAST_ASSERT_DSTATE 
};
TraceEvent _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_EVENT = {
    .id = 0,
    .vcpu_id = TRACE_VCPU_EVENT_NONE,
    .name = "object_class_dynamic_cast_assert",
    .sstate = TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_ENABLED,
    .dstate = &_TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE 
};
TraceEvent *qom_trace_events[] = {
    &_TRACE_OBJECT_DYNAMIC_CAST_ASSERT_EVENT,
    &_TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_EVENT,
  NULL,
};

static void trace_qom_register_events(void)
{
    trace_event_register_group(qom_trace_events);
}
trace_init(trace_qom_register_events)
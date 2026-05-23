// SPDX-License-Identifier: GPL-2.0
//
// DragonKeep eBPF process-trace program.
//
// Attaches to the sched_process_exec tracepoint and ships pid + ppid +
// comm[16] + first 256 bytes of args to userspace via a ring buffer.
// User-space (src/engine/behavioral_ebpf.rs) consumes events and feeds
// them into the behavioral evaluator with sub-microsecond latency.
//
// Build:
//   - bpf-helpers from libbpf headers
//   - vmlinux.h generated via bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   - libbpf-cargo handles the rest at build time (build.rs)
//
// Activated by: feature = "ebpf" + CAP_BPF + /sys/kernel/btf/vmlinux present
//
// Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define ARG_MAX 256

struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 ts_ns;
    char comm[16];
    char args[ARG_MAX];
};

// Ring buffer for events (256 KB).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Per-CPU scratch event to avoid stack-blowing.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct event);
    __uint(max_entries, 1);
} scratch SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u32 zero = 0;
    struct event *e;

    e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Parent PID via task_struct->real_parent->tgid (CO-RE).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read args from the tracepoint context. The kernel exposes
    // ctx->filename — full argv would require probing __bprm_args.
    bpf_probe_read_kernel_str(&e->args, sizeof(e->args), (void *)&ctx->__data);

    // Submit to ring buffer (drops on full — we don't block kernel paths).
    struct event *out = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!out) return 0;
    __builtin_memcpy(out, e, sizeof(*e));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

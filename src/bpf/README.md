# DragonKeep eBPF programs

Source for the kernel-side programs the NGAV stack loads on Linux when
`feature = "ebpf"` is enabled at build time.

## Files

| File | Attach point | Purpose |
|---|---|---|
| `process_trace.bpf.c` | `tracepoint/sched/sched_process_exec` | Ships every exec() to userspace via ring buffer |

## Build prerequisites

- Linux 5.13+ (BPF CO-RE)
- `clang` + `llvm`
- `bpftool` (from `linux-tools-common` on Debian/Ubuntu)
- `libbpf-dev`

## Generate `vmlinux.h`

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

This file is per-kernel and not committed. The CI workflow regenerates
it on each build.

## Userspace consumer

`src/engine/behavioral_ebpf.rs` uses [libbpf-rs](https://github.com/libbpf/libbpf-rs)
to compile + load + attach the program, then drains the ring buffer
into [`engine::behavioral::evaluate`](../engine/behavioral.rs).

## Why not eBPF by default?

- Requires root or CAP_BPF
- Requires BTF (`/sys/kernel/btf/vmlinux`) — missing in containers/embedded
- Build chain is non-trivial; the `sysinfo`-based fallback covers 95 % of operators

`feature = "ebpf"` opts you in once you have the toolchain wired.

Copyright 2026 Ghost Protocol (Pvt) Ltd · ryan@ghosts.lk

// build.rs · only does work when `feature = "ebpf"` is enabled
// (Spec 002 · dragon-platform).
//
// Compiles src/bpf/process_trace.bpf.c and generates a skel at
// src/bpf/process_trace.skel.rs that the userspace loader consumes.

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/process_trace.bpf.c");

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        use libbpf_cargo::SkeletonBuilder;
        use std::path::PathBuf;

        let src = PathBuf::from("src/bpf/process_trace.bpf.c");
        let out = PathBuf::from("src/bpf/process_trace.skel.rs");
        SkeletonBuilder::new()
            .source(&src)
            .build_and_generate(&out)
            .expect("failed to generate BPF skeleton — is clang + libbpf-dev installed?");
    }
}

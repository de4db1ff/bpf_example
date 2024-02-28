#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

unsigned long long dev, ino;


SEC("ksyscall/kill")
int BPF_KSYSCALL(entry_probe, pid_t pid, int sig)
{
	struct bpf_pidns_info ns;
	char comm[TASK_COMM_LEN];

	bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));
	__u32 caller_pid = ns.pid;

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("KILL syscall called by PID %d (%s).", caller_pid, comm);
	return 0;
}

char _license[] SEC("license") = "GPL";

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "ksyscall.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main(int argc, char **argv)
{
	struct ksyscall_bpf *skel;
	int err;
	struct stat sb;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = ksyscall_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* namespace-aware, fix problems when running in namespace */
	if (stat("/proc/self/ns/pid", &sb) == -1) {
		fprintf(stderr, "Failed to acquire namespace information");
		return 1;
	}
	/* Set the global vars in bpf */
	skel->bss->dev = sb.st_dev;
	skel->bss->ino = sb.st_ino;

	/* Load and verify BPF application */
	err = ksyscall_bpf__load(skel);
        if (err) {
                fprintf(stderr, "Failed to load and verify BPF skeleton\n");
                return 1;
        }

	/* Attach tracepoint handler */
	err = ksyscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	system("cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
	ksyscall_bpf__destroy(skel);
	return -err;
}

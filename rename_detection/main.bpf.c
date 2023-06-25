#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");



SEC("kprobe/do_renameat2")
int probe_renameat2(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.op_code = 3;

    struct filename *from = (struct filename *)PT_REGS_PARM2(ctx);
    struct filename *to = (struct filename *)PT_REGS_PARM4(ctx);


    bpf_probe_read(&data.oldpath, sizeof(data.oldpath), BPF_CORE_READ(from, name));
    bpf_probe_read(&data.newpath, sizeof(data.newpath), BPF_CORE_READ(to, name));

    bpf_ringbuf_output(&ringbuf, &data, sizeof(data), BPF_RB_FORCE_WAKEUP);

    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

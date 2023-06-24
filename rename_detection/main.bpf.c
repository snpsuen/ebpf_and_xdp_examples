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
    const char *old_name = &data.oldpath[0];
    const char *new_name = &data.newpath[0];
    
    bpf_probe_read(&old_name, sizeof(data.oldpath), &from->name);
    int ret_old = bpf_probe_read(&data.oldpath, sizeof(data.oldpath), old_name);

    bpf_probe_read(&new_name, sizeof(data.newpath), &to->name);
    int ret_new = bpf_probe_read(&data.newpath, sizeof(data.newpath), new_name);
    
    bpf_ringbuf_output(&ringbuf, &data, sizeof(data), BPF_RB_FORCE_WAKEUP);


    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    data.pid = bpf_get_current_pid_tgid();
    data.uid = uid;
    data.op_code = 3;

    struct filename *from = (struct filename *)PT_REGS_PARM2_SYSCALL(ctx);
    struct filename *to = (struct filename *)PT_REGS_PARM4_SYSCALL(ctx);
    const char *old_name = data.oldpath;
    const char *new_name = data.newpath;
    
    bpf_probe_read(&old_name, sizeof(old_name), &from->name);
    int ret_old = bpf_probe_read(&data.oldpath, sizeof(data.oldpath), old_name);

    bpf_probe_read(&new_name, sizeof(new_name), &to->name);
    int ret_new = bpf_probe_read(&data.newpath, sizeof(data.newpath), new_name);
    
    data.debug = ret_old < 0 ? ret_old : ret_new;

    bpf_ringbuf_output(&ringbuf, &data, sizeof(data), BPF_RB_FORCE_WAKEUP);


    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

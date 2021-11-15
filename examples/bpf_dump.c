#include <linux/sched.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

int trace_entry(struct pt_regs* ctx, int dfd, const char __user* filename) {
    bpf_trace_printk("hello from rust\\n");
    return 0;
}
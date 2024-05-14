from bcc import BPF
code = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32, u64); 

int probe_handler(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid();
    start.update(&tgid, &ts);  
    return 0;
}

int end_function(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid();
    u64 *start_ts = start.lookup(&tgid); 
    if (start_ts) {
        bpf_trace_printk("duration %llu\\n", ts - *start_ts); 
        start.delete(&tgid);  
    }
    return 0;
}

"""

b = BPF(text = code)
b.attach_kprobe(event = 'my_thread_run', fn_name = 'probe_handler')
b.attach_kretprobe(event = 'my_thread_run', fn_name = 'end_function')

while True:
	try:
		res = b.trace_fields()
	except ValueError:
		print(res)
		continue
	print(res[5].decode("UTF-8"))
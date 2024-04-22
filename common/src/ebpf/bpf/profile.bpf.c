// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "profile.bpf.h"
#include "pid.h"
#include "ume.h"

#define PF_KTHREAD 0x00200000

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 tgid = 0;
    current_pid(&tgid);
    struct sample_key key = {};
    u32 *val, one = 1;
    bpf_dbg_printk("do_perf_event\n");
    //  u64 bpf_get_current_task(void)
    //     Description
    //         Get the current task.
    //     Return A pointer to the current task struct.

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (tgid == 0 || task == 0) {
        return 0;
    }

    //  long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)
    //     Description
    //         Safely attempt to read size bytes from kernel space
    //         address unsafe_ptr and store the data in dst.
    //     Return 0 on success, or a negative error in case of failure.

    int flags = 0;
    if (bpf_probe_read_kernel(&flags, sizeof(flags), &task->flags)) {
        bpf_dbg_printk("failed to read task->flags\n");
        return 0;
    }

    if (flags & PF_KTHREAD) {
        bpf_dbg_printk("skipping kthread %d\n", tgid);
        return 0;
    }

    // void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
    //     Description
    //         Perform a lookup in map for an entry associated to key.
    //      Return Map value associated to key, or NULL if no entry was found.

    struct pid_config *config = bpf_map_lookup_elem(&pids, &tgid);
    if (config == NULL) {
        struct pid_config unknown = {
                .profile_type = PROFILING_TYPE_UNKNOWN,
                .collect_kernel = 0,
                .collect_user = 0,
                .padding_ = 0
        };
        if (bpf_map_update_elem(&pids, &tgid, &unknown, BPF_NOEXIST)) {
            bpf_dbg_printk("failed to update pids map. probably concurrent update\n");
            return 0;
        }
        struct pid_event event = {
                .op  = OP_REQUEST_UNKNOWN_PROCESS_INFO,
                .pid = tgid
        };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
    }

    if (config->profile_type == PROFILING_TYPE_ERROR || config->profile_type == PROFILING_TYPE_UNKNOWN) {
        return 0;
    }

    if (config->profile_type == PROFILING_TYPE_PYTHON) {
        bpf_tail_call(ctx, &progs, PROG_IDX_PYTHON);
        return 0;
    }

    if (config->profile_type == PROFILING_TYPE_FRAMEPOINTERS) {
        key.pid = tgid;
        key.kern_stack = -1;
        key.user_stack = -1;

        if (config->collect_kernel) {
            key.kern_stack = bpf_get_stackid(ctx, &stacks, KERN_STACKID_FLAGS);
        }
        if (config->collect_user) {
            key.user_stack = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS);
        }

        val = bpf_map_lookup_elem(&counts, &key);
        if (val)
            (*val)++;
        else
            bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }
    return 0;
}


SEC("kprobe/disassociate_ctty")
int BPF_KPROBE(disassociate_ctty, int on_exit) {
    bpf_dbg_printk("kprobe/disassociate_ctty\n");
    if (!on_exit) {
        return 0;
    }
    u32 pid = 0;
    current_pid(&pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
        .op  = OP_PID_DEAD,
        .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/" SYS_PREFIX "sys_execve")
int BPF_KPROBE(execve, void *_) {
    bpf_dbg_printk("kprobe/sys_execve\n");
    u32 pid = 0;
    current_pid(&pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
            .op  = OP_REQUEST_EXEC_PROCESS_INFO,
            .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/" SYS_PREFIX "sys_execveat")
int BPF_KPROBE(execveat, void *_) {
    bpf_dbg_printk("kprobe/sys_execveat\n");
    u32 pid = 0;
    current_pid(&pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
            .op  = OP_REQUEST_EXEC_PROCESS_INFO,
            .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "pid.h"
#include "ume.h"


struct sample_key {
    __u32 pid;
    __u32 flags;
    __s64 kern_stack;
    __s64 user_stack;
};

#define PROFILING_TYPE_UNKNOWN 1
#define PROFILING_TYPE_FRAMEPOINTERS 2
#define PROFILING_TYPE_PYTHON 3
#define PROFILING_TYPE_ERROR 4

struct pid_config {
    uint8_t profile_type;
    uint8_t collect_user;
    uint8_t collect_kernel;
    uint8_t padding_;
};
struct pid_config p__;

#define OP_REQUEST_UNKNOWN_PROCESS_INFO 1
#define OP_PID_DEAD 2
#define OP_REQUEST_EXEC_PROCESS_INFO 3

struct pid_event {
    uint32_t op;
    uint32_t pid;
};
struct pid_event e__;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct pid_config);
    __uint(max_entries, 1024);
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __array(values, int (void *));
} progs SEC(".maps");

#define PROG_IDX_PYTHON 0

#include "stacks.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sample_key);
    __type(value, u32);
    __uint(max_entries, PROFILE_MAPS_SIZE);
} counts SEC(".maps");

#define PF_KTHREAD 0x00200000

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 tgid = 0;
    current_pid(&tgid);

    struct sample_key key = {};
    u32 *val, one = 1;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (tgid == 0 || task == 0) {
        return 0;
    }
    int flags = 0;
    if (pyro_bpf_core_read(&flags, sizeof(flags), &task->flags)) {
        bpf_dbg_printk("failed to read task->flags\n");
        return 0;
    }
    if (flags & PF_KTHREAD) {
        bpf_dbg_printk("skipping kthread %d\n", tgid);
        return 0;
    }

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

// execve/execveat
SEC("kprobe/exec")
int BPF_KPROBE(exec, void *_) {
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

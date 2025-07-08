import multiprocessing
import socket
import mmap
import struct
from bcc import BPF
import ctypes as ct
import os
import signal
import time

print("start")
EXEC_PATH = input("Enter path to executable: ").strip()
start_time = time.time()

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define TASK_RUNNING        0x00000000
#define TASK_INTERRUPTIBLE  0x00000001
#define TASK_UNINTERRUPTIBLE 0x00000002
#define TASK_DEAD           0x00000080
#define TASK_WAKEKILL       0x00000100
#define TASK_WAKING         0x00000200

struct SchedStats {
    u64 total_ready_time;
    u64 total_blocked_time;
    u64 total_swapped_time;
    u64 total_running_time;
    u16 previous_state;
    u64 previous_time;
    u64 start_time;
};

struct PageEventStats {
    u64 fault_count;
    u64 swap_out_count;
};

BPF_HASH(counter, u32, struct SchedStats);
BPF_HASH(pagefaults, u32, struct PageEventStats);
BPF_HASH(target_pid, u32, u32);

static __inline u64 get_time() {
    return bpf_ktime_get_ns()/1000000;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    long prev_state = args->prev_state;
    u32 zero = 0;
    u64 current_time = get_time();

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr)
        return 0;

    if (*my_pid_ptr == prev_pid) {
        struct SchedStats *s = counter.lookup(&prev_pid);
        if (!s) {
            struct SchedStats init = {};
            init.previous_time = current_time;
            counter.update(&prev_pid, &init);
            s = counter.lookup(&prev_pid);
            if (!s) return 0;
        }

        if (prev_state == TASK_RUNNING) {
            s->previous_state = 0;
        } else if (prev_state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE | TASK_WAKEKILL)) {
            s->previous_state = 1;
        } else if (prev_state & TASK_DEAD) {
            s->previous_state = 2;
        }

        s->total_running_time += current_time - s->previous_time;
        s->previous_time = current_time;
    } else if (*my_pid_ptr == next_pid) {
        struct SchedStats *s = counter.lookup(&next_pid);
        if (!s) {
            struct SchedStats init = {};
            init.previous_time = current_time;
            counter.update(&next_pid, &init);
            return 0; // Don't try to use 'delta' in the same call
        }

        if (s->previous_state == 0) {
            s->total_ready_time += current_time - s->previous_time;
        } else if (s->previous_state == 1) {
            s->total_blocked_time += current_time - s->previous_time;
        } else {
            s->total_swapped_time += current_time - s->previous_time;
        }
        s->previous_time = current_time;
    }

    return 0;
}

TRACEPOINT_PROBE(exceptions, page_fault_user) {
    //bpf_trace_printk("page_fault");
    u32 pid = bpf_get_current_pid_tgid();
    u32 zero = 0;

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr || pid != *my_pid_ptr)
        return 0;

    struct PageEventStats *stats = pagefaults.lookup(&pid);
    if (stats) {
        stats->fault_count += 1;
    } else {
        struct PageEventStats init = {};
        init.fault_count = 1;
        pagefaults.update(&pid, &init);
    }

    return 0;
}

TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_reclaim_begin){
    //bpf_trace_printk("reclaim");
    u32 pid = bpf_get_current_pid_tgid();
    u32 zero = 0;

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr || pid != *my_pid_ptr)
        return 0;

    struct PageEventStats *stats = pagefaults.lookup(&pid);
    if (stats) {
        stats->swap_out_count += 1;
    } else {
        struct PageEventStats init = {};
        init.swap_out_count = 1;
        pagefaults.update(&pid, &init);
    }

    return 0;
}

TRACEPOINT_PROBE(vmscan, mm_vmscan_memcg_softlimit_reclaim_begin){
    //bpf_trace_printk("reclaim");
    u32 pid = bpf_get_current_pid_tgid();
    u32 zero = 0;

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr || pid != *my_pid_ptr)
        return 0;

    struct PageEventStats *stats = pagefaults.lookup(&pid);
    if (stats) {
        stats->swap_out_count += 1;
    } else {
        struct PageEventStats init = {};
        init.swap_out_count = 1;
        pagefaults.update(&pid, &init);
    }

    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    u32 pid = args->pid;
    u32 zero = 0;
    u64 now = get_time();

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr || pid != *my_pid_ptr)
        return 0;

    struct SchedStats *s = counter.lookup(&pid);
    if (!s) {
        struct SchedStats init = {};
        init.start_time = now;
        init.previous_state = 0;
        init.previous_time = now;
        counter.update(&pid, &init);
    } else {
        if (s->start_time == 0)
            s->start_time = now;
        s->previous_state = 0;
    }

    return 0;
}


"""

b = BPF(text=bpf_code)

cgroup_path = "/sys/fs/cgroup/mygroup/cgroup.procs"
with open(cgroup_path, "w") as f:
    f.write(str(os.getpid()))

pid = os.fork()
if pid == 0:
    os.execv(EXEC_PATH, [EXEC_PATH])
else:
    child_pid = pid
    SHM_SIZE = 1024  # enough for a few stats
    STATS_STRUCT = struct.Struct("d d d d Q Q d")  # ready, blocked, swapped, running, faults,resident page ratio

def send_stats_to_server(child_pid, shm_key, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", port))
    sock.send(shm_key.encode())
    sock.close()

def second_child_fn(child_pid):
    shm_key = f"/shm_{child_pid}"
    fd = os.open("/dev/shm" + shm_key, os.O_CREAT | os.O_RDWR)
    os.ftruncate(fd, SHM_SIZE)
    mem = mmap.mmap(fd, SHM_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE)

    send_stats_to_server(child_pid, shm_key, 9000)
    send_stats_to_server(child_pid, shm_key, 9001)

    while True:
        key = ct.c_uint(child_pid)
        stats = b["counter"].get(key)
        mem_stats = b["pagefaults"].get(key)
        faults = mem_stats.fault_count if mem_stats else 0
        swap_outs = mem_stats.swap_out_count if mem_stats else 0

        vmrss = 0
        vmswap = 0
        status_path = f"/proc/{child_pid}/status"
        if os.path.exists(status_path):
            with open(status_path) as f:
                lines = f.readlines()
                for line in lines:
                    if "VmRSS:" in line:
                        vmrss = int(line.split()[1])
                    elif "VmSwap:" in line:
                        vmswap = int(line.split()[1])

        if stats:
            total_time = (
                stats.total_running_time +
                stats.total_ready_time +
                stats.total_blocked_time +
                stats.total_swapped_time
            )

            data1 = struct.pack(
                "d d d d",
                stats.total_ready_time / total_time,
                stats.total_blocked_time / total_time,
                stats.total_swapped_time / total_time,
                stats.total_running_time / total_time
            )

            data2 = struct.pack(
                "Q Q d",
                int(faults),
                int(swap_outs),
                vmrss / (vmrss + vmswap) if (vmrss + vmswap) > 0 else 0
            )

            mem.seek(0)
            mem.write(data1 + data2)
            mem.flush()

        time.sleep(0.7)
    exit(0)

with open("/sys/fs/cgroup/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))

b["target_pid"][ct.c_uint(0)] = ct.c_uint(child_pid)
nice_level = 0
sched_stage = 0

print(f"Tracking child PID: {child_pid}")

class SchedStats(ct.Structure):
    _fields_ = [
        ("total_ready_time", ct.c_ulonglong),
        ("total_blocked_time", ct.c_ulonglong),
        ("total_swapped_time", ct.c_ulonglong),
        ("total_running_time", ct.c_ulonglong),
        ("previous_state", ct.c_ushort),
        ("previous_time", ct.c_ulonglong),
    ]

second_pid = os.fork()
if second_pid == 0:
    second_child_fn(child_pid)
    exit(0)
    
def print_stats():
    elapsed_time = time.time() - start_time
    key = ct.c_uint(child_pid)
    stats = b["counter"].get(key)
    mem_stats = b["pagefaults"].get(key)

    faults = mem_stats.fault_count if mem_stats else 0
    swaps = mem_stats.swap_out_count if mem_stats else 0

    if stats:
        elapsed_time = time.time() / 1000000 - stats.start_time
        total_time = (
            stats.total_ready_time +
            stats.total_blocked_time +
            stats.total_swapped_time +
            stats.total_running_time
        )

        print(f"Ready: {stats.total_ready_time:.2f} ms, Blocked: {stats.total_blocked_time:.2f} ms, Swapped: {stats.total_swapped_time:.2f} ms, Running: {stats.total_running_time:.2f} ms")
        print(f"Total Observed Time: {total_time:.2f} ms, Page Faults: {faults}, Faults/sec: {faults / elapsed_time:.2f}")
        print(f"Swaps: {swaps}, Swaps/sec: {swaps / elapsed_time:.2f }")
    else:
        print("No switch stats collected")

    status_path = f"/proc/{child_pid}/status"
    if os.path.exists(status_path):
        with open(status_path) as f:
            lines = f.readlines()
            rss = [l for l in lines if "VmRSS" in l]
            swap = [l for l in lines if "VmSwap" in l]
            rss = rss[0].strip() if rss else "VmRSS: unknown"
            swap = swap[0].strip() if swap else "VmSwap: unknown"
        print(rss)
        print(swap)
    else:
        print("Process exited: VmRSS and VmSwap unavailable")

def boost_priority():
    global nice_level, sched_stage
    if sched_stage == 0:
        if nice_level > -19:
            nice_level -= 5
            os.system(f"renice -n {nice_level} -p {child_pid}")
            print(f"Updated nice to {nice_level}")
        else:
            class SchedParam(ct.Structure):
                _fields_ = [("sched_priority", ct.c_int)]
            param = SchedParam()
            param.sched_priority = 10
            libc = ct.CDLL("libc.so.6")
            res = libc.sched_setscheduler(child_pid, 2, ct.byref(param))
            if res != 0:
                print("sched_setscheduler failed")
            else:
                sched_stage = 1
                print("Switched to SCHED_RR")
    else:
        class SchedParam(ct.Structure):
            _fields_ = [("sched_priority", ct.c_int)]
        param = SchedParam()
        param.sched_priority = 20
        libc = ct.CDLL("libc.so.6")
        res = libc.sched_setscheduler(child_pid, 2, ct.byref(param))
        if res != 0:
            print("sched_setscheduler failed")
        else:
            print("Increased SCHED_RR priority")

def reduce_oom_score():
    current_oom_score = int(open(f"/proc/{child_pid}/oom_score").read().strip())
    new_oom_score = current_oom_score - 100
    
    # Ensure the new oom_score is within the valid range (-1000 to 1000)
    new_oom_score = max(-1000, min(1000, new_oom_score))
    
    # Update the oom_score_adj to make it less likely to be killed
    with open(f"/proc/{child_pid}/oom_score_adj", "w") as f:
        f.write(str(new_oom_score))
    
    print(f"Reduced OOM score of process {child_pid} by 100, new score: {new_oom_score}")

def handle_exit(sig, frame):
    print_stats()
    os.kill(child_pid, 9)
    os.kill(second_pid, 9)
    exit(0)

signal.signal(signal.SIGINT, handle_exit)

while True:
    print("\n[p] Boost Priority  [o] reduce OOM score  [m] lock current pages [s] Stats  [q] Quit")
    ch = input("> ").strip()
    if ch == 'p':
        boost_priority()
    elif ch == 'm':
        reduce_oom_score()
    elif ch == 's':
        print_stats()
    elif ch == 'q':
        handle_exit(None, None)


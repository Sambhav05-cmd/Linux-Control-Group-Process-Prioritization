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

BPF_HASH(counter, u32, u64);
BPF_HASH(pagefaults, u32, u64);
BPF_HASH(target_pid, u32, u32);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 zero = 0;

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr) return 0;

    if (prev_pid == *my_pid_ptr) {
        u64 *val = counter.lookup(&prev_pid);
        if (val) (*val) += 1;
        else {
            u64 one = 1;
            counter.update(&prev_pid, &one);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(exceptions, page_fault_user) {
    u32 pid = bpf_get_current_pid_tgid();
    u32 zero = 0;

    u32 *my_pid_ptr = target_pid.lookup(&zero);
    if (!my_pid_ptr) return 0;

    if (pid == *my_pid_ptr) {
        u64 *val = pagefaults.lookup(&pid);
        if (val) (*val) += 1;
        else {
            u64 one = 1;
            pagefaults.update(&pid, &one);
        }
    }
    return 0;
}
"""

b = BPF(text=bpf_code)

pid = os.fork()
if pid == 0:
    os.execv(EXEC_PATH, [EXEC_PATH])
    print("exec failed")
    os._exit(1)
else:
    child_pid = pid
    b["target_pid"][ct.c_uint(0)] = ct.c_uint(child_pid)

    nice_level = 0
    sched_stage = 0

    print(f"Tracking child PID: {child_pid}")

    def print_stats():
        elapsed_time = time.time() - start_time
        key = ct.c_uint(child_pid)
        switches = b["counter"].get(key)
        faults = b["pagefaults"].get(key)
        switches = switches.value if switches else 0
        faults = faults.value if faults else 0

        print(f"Switches: {switches}, Page Faults: {faults}")
        if elapsed_time > 0:
            print(f"Switches/sec: {switches / elapsed_time:.2f}, Faults/sec: {faults / elapsed_time:.2f}")

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

    def reduce_swap():
        os.system(f"echo 1 > /proc/{child_pid}/clear_refs")
        print("Triggered memory refresh to reduce swap")

    def handle_exit(sig, frame):
        print_stats()
        os.kill(child_pid, 9)
        exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    while True:
        print("\n[p] Boost Priority  [m] Reduce Swap  [s] Stats  [q] Quit")
        ch = input("> ").strip()
        if ch == 'p':
            boost_priority()
        elif ch == 'm':
            reduce_swap()
        elif ch == 's':
            print_stats()
        elif ch == 'q':
            handle_exit(None, None)  

import os, time, subprocess, signal
import ctypes as ct
from bcc import BPF

IMAGE_NAME = "memcpu-test-img"
CONTAINER_NAME = "memcpu-test-container"
MEM_DELTA = 1 * 1024 * 1024
CPU_DELTA = 1000
CPU_PERIOD = 100000
ITERATIONS = 100

def get_pid_by_name(name):
    out = subprocess.check_output(["pidof", name]).decode().strip()
    return [int(p) for p in out.split()]

def get_container_pid(container_id):
    result = subprocess.run(
        ['docker', 'inspect', '--format', '{{.State.Pid}}', container_id],
        stdout=subprocess.PIPE, check=True
    )
    return int(result.stdout.decode().strip())

def get_cgroup_path(pid):
    cgroup_file = f"/proc/{pid}/cgroup"
    with open(cgroup_file, "r") as f:
        lines = f.readlines()
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) == 3 and parts[1] in ["memory", ""]:
            rel_path = parts[2].lstrip("/")
            unified_path = f"/sys/fs/cgroup/{rel_path}"
            if os.path.exists(unified_path):
                return unified_path
            mem_path = f"/sys/fs/cgroup/memory/{rel_path}"
            if os.path.exists(mem_path):
                return mem_path
    raise RuntimeError("Cgroup path not found")

subprocess.run(["docker", "build", "-t", IMAGE_NAME, "."], cwd="./docker-test", check=True)
subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run([
    "docker", "run", "-d",
    "--cgroupns=host",
    "--name", CONTAINER_NAME,
    IMAGE_NAME
], check=True)

container_id = subprocess.check_output(
    ["docker", "inspect", "--format", "{{.Id}}", CONTAINER_NAME]
).decode().strip()

pid = get_container_pid(container_id)
cgroup_path = get_cgroup_path(pid)
memory_file = os.path.join(cgroup_path, "memory.max")
cpu_file = os.path.join(cgroup_path, "cpu.max")

dockerd_pid = get_pid_by_name("dockerd")[0]

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define NAME_BUF_LEN 32
BPF_HASH(start_ts, u32, u64);
BPF_HASH(last_write_ts, u32, u64);

int trace_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != DOCKERD_PID) return 0;
    u32 key = 0;
    u64 now = bpf_ktime_get_ns();
    start_ts.update(&key, &now);
    bpf_trace_printk("ENTRY dockerd pid=%d ts=%llu\\n", pid, now);
    return 0;
}

int trace_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    struct dentry *dentry = file->f_path.dentry;
    char filename[NAME_BUF_LEN];
    bpf_probe_read_str(&filename, sizeof(filename), dentry->d_name.name);

    if (
        (
            filename[0]=='m'&&filename[1]=='e'&&filename[2]=='m'&&filename[3]=='o'&&
            filename[4]=='r'&&filename[5]=='y'&&filename[6]=='.'&&filename[7]=='m'&&
            filename[8]=='a'&&filename[9]=='x'&&!filename[10]
        ) ||
        (
            filename[0]=='c'&&filename[1]=='p'&&filename[2]=='u'&&filename[3]=='.'&&
            filename[4]=='m'&&filename[5]=='a'&&filename[6]=='x'&&!filename[7]
        )
    ) {
        u32 key = 0;
        u64 now = bpf_ktime_get_ns();
        u64 *start = start_ts.lookup(&key);
        if (start) {
            u64 delta = now - *start;
            last_write_ts.update(&key, &delta);
            start_ts.delete(&key);
            bpf_trace_printk("EXIT filename=%s pid=%d delta=%llu\\n", filename, bpf_get_current_pid_tgid() >> 32, delta);
        } else {
            bpf_trace_printk("EXIT filename=%s pid=%d no_start\\n", filename, bpf_get_current_pid_tgid() >> 32);
        }
    }
    return 0;
}
"""

b = BPF(text=bpf_code.replace("DOCKERD_PID", str(dockerd_pid)))

recv_symbols = [
    "__x64_sys_recvmsg",
    "__sys_recvmsg",
    "sys_recvmsg",
    "sock_recvmsg",
    "__x64_sys_recvmmsg",
    "__sys_recvmmsg",
    "recvmmsg"
]

for sym in recv_symbols:
    try:
        b.attach_kprobe(event=sym, fn_name="trace_recvmsg")
    except Exception:
        print(sym)

b.attach_kprobe(event="vfs_write", fn_name="trace_write")

mem_latencies = []
cpu_latencies = []

initial_mem = 128 * 1024 * 1024
high_mem = initial_mem + MEM_DELTA
initial_cpu = 10000

subprocess.run([
    "docker", "update",
    "--memory", str(initial_mem),
    "--memory-swap", str(2 * high_mem),
    "--cpus", f"{initial_cpu / CPU_PERIOD:.3f}",
    CONTAINER_NAME
], check=True)

def wait_for_delta():
    for _ in range(10000):
        val = b["last_write_ts"].get(ct.c_uint(0))
        if val:
            delta = val.value
            try:
                del b["last_write_ts"][ct.c_uint(0)]
            except Exception:
                pass
            return delta
        #time.sleep(0.0005)
    return None

for i in range(ITERATIONS):
    mem = initial_mem + (MEM_DELTA if i % 2 == 0 else -MEM_DELTA)
    cpu = initial_cpu + (CPU_DELTA if i % 2 == 0 else -CPU_DELTA)

    subprocess.run(["docker", "update", "--memory", str(mem), CONTAINER_NAME], check=True)
    delta = wait_for_delta()
    if delta:
        mem_latencies.append(delta / 1e6)

    cpu_str = f"{cpu / CPU_PERIOD:.3f}"
    subprocess.run(["docker", "update", "--cpus", cpu_str, CONTAINER_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    delta = wait_for_delta()
    if delta and i > 0:
        cpu_latencies.append(delta / 1e6)

if mem_latencies:
    avg_mem = sum(mem_latencies) / len(mem_latencies)
else:
    avg_mem = float('nan')

if cpu_latencies:
    avg_cpu = sum(cpu_latencies) / len(cpu_latencies)
else:
    avg_cpu = float('nan')

print(f"\nAvg memory.max latency (dockerd recvmsg → cgroup write): {avg_mem:.3f} ms")
print(f"Avg cpu.max latency (dockerd recvmsg → cgroup write):    {avg_cpu:.3f} ms")

raw_latencies = []
for i in range(ITERATIONS):
    now_ns = time.monotonic_ns()
    b["start_ts"][ct.c_uint(0)] = ct.c_ulonglong(now_ns)

    with open(memory_file, "w") as f:
        f.write(str(high_mem))

    delta = wait_for_delta()
    if delta and i > 0:
        raw_latencies.append(delta / 1e6)

    #time.sleep(0.01)

if raw_latencies:
    avg_raw = sum(raw_latencies) / len(raw_latencies)
else:
    avg_raw = float('nan')

print(f"\nAvg raw memory.max write latency: {avg_raw:.3f} ms")

subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], stdout=subprocess.DEVNULL)


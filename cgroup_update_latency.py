import os, time, subprocess
import ctypes as ct
from bcc import BPF

IMAGE_NAME = "memcpu-test-img"
CONTAINER_NAME = "memcpu-test-container"
MEM_DELTA = 1 * 1024 * 1024
CPU_DELTA = 1000
CPU_PERIOD = 100000
ITERATIONS = 100

print("Building image...")
subprocess.run(["docker", "build", "-t", IMAGE_NAME, "."], cwd="./docker-test", check=True)

print("Cleaning any existing container...")
subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print("Running container...")
subprocess.run([
    "docker", "run", "-d",
    "--cgroupns=host",
    "--name", CONTAINER_NAME,
    IMAGE_NAME
], check=True)

print("Locating container cgroup paths...")
pid = subprocess.check_output(["docker", "inspect", "--format", "{{.State.Pid}}", CONTAINER_NAME]).decode().strip()
with open(f"/proc/{pid}/cgroup", "r") as f:
    lines = f.readlines()

cg_rel_path = None
for line in lines:
    parts = line.strip().split(":")
    if len(parts) == 3:
        subsystems, path = parts[1], parts[2]
        if "memory" in subsystems or subsystems == "":
            cg_rel_path = path
            break

if not cg_rel_path:
    raise RuntimeError("Could not determine cgroup path")

memory_file = f"/sys/fs/cgroup{cg_rel_path}/memory.max"
cpu_file = f"/sys/fs/cgroup{cg_rel_path}/cpu.max"

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#define NAME_BUF_LEN 32
BPF_HASH(last_write_ts, u32, u64);

int trace_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    struct dentry *dentry = file->f_path.dentry;
    const char *name = dentry->d_name.name;
    char filename[NAME_BUF_LEN];
    bpf_probe_read_str(&filename, sizeof(filename), name);

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
        last_write_ts.update(&key, &now);
    }

    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_kprobe(event="vfs_write", fn_name="trace_write")

print("Starting latency measurement...")
mem_latencies = []
cpu_latencies = []

initial_mem = 128 * 1024 * 1024
high_mem = initial_mem + MEM_DELTA
initial_cpu = 10000

def write_cgroup_file(path, value):
    with open(path, "w") as f:
        f.write(str(value))

def wait_for_write(old_ts):
    for _ in range(10000):
        val = b["last_write_ts"].get(ct.c_uint(0))
        if val and val.value != old_ts:
            return val.value
    return None

write_cgroup_file(memory_file, str(initial_mem))
write_cgroup_file(cpu_file, f"{initial_cpu} {CPU_PERIOD}")

for i in range(ITERATIONS):
    mem = initial_mem + (MEM_DELTA if i % 2 == 0 else -MEM_DELTA)
    cpu = initial_cpu + (CPU_DELTA if i % 2 == 0 else -CPU_DELTA)

    old_ts = b["last_write_ts"].get(ct.c_uint(0))
    old_ts = old_ts.value if old_ts else 0
    t0 = time.monotonic_ns()
    write_cgroup_file(memory_file, str(mem))
    t1 = wait_for_write(old_ts)
    if t1:
        mem_latencies.append((t1 - t0) / 1e6)

    old_ts = b["last_write_ts"].get(ct.c_uint(0))
    old_ts = old_ts.value if old_ts else 0
    t0 = time.monotonic_ns()
    write_cgroup_file(cpu_file, f"{cpu} {CPU_PERIOD}")
    t1 = wait_for_write(old_ts)
    if t1:
        cpu_latencies.append((t1 - t0) / 1e6)

avg_mem = sum(mem_latencies) / len(mem_latencies)
avg_cpu = sum(cpu_latencies) / len(cpu_latencies)

print(f"\nAverage memory.max latency via cgroup write: {avg_mem:.3f} ms")
print(f"Average cpu.max latency via cgroup write:    {avg_cpu:.3f} ms")

subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], stdout=subprocess.DEVNULL)


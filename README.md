# Docker Resource Control Optimization

**Technologies:** Docker, eBPF, Linux Cgroups, Python

---

## Project Overview
This project implements a **real-time resource control framework for Docker**. Its primary goal is to **dramatically reduce latency when updating container CPU and memory limits** by bypassing Docker's userspace (`dockerd`) and writing directly to the Linux cgroup files (`memory.max` and `cpu.max`).  

By using this method, we achieve **∼1000× lower latency** compared to the standard `docker update` command (8.938 ms → 0.006 ms).

The framework also dynamically adjusts CPU and memory limits for running processes, changes CPU scheduling priorities, and monitors system behavior in real-time using **eBPF**.

---

## Why This Matters
In containerized environments, applications often need rapid resource scaling. Standard Docker updates go through `dockerd`, which introduces additional latency due to userspace processing, scheduling, and syscall overhead. This can:

- Cause delays in meeting application resource requirements  
- Lead to inefficient resource usage  
- Affect performance-sensitive workloads  

This project shows that **kernel-level enforcement using cgroups v2** can drastically reduce latency while still allowing dynamic and safe resource adjustments.

---

## Measuring Docker Update Latency
To understand the inherent latency in Docker's `update` command, we need to measure **from the moment `dockerd` receives the request until the kernel enforces the new limits**. The approach:

1. **Trace Docker daemon socket receive:**  
   - Attach eBPF kprobes to `recvmsg` and `recvmmsg` syscalls of `dockerd`.  
   - This captures the exact timestamp when the update request enters `dockerd`.

2. **Trace kernel file write (`vfs_write`)**:  
   - Attach an eBPF kprobe to `vfs_write`.  
   - Filter for `memory.max` and `cpu.max` writes corresponding to the container's cgroup.  
   - This captures the timestamp when the kernel actually enforces the new limit.

3. **Calculate latency:**  
   - Latency = `vfs_write timestamp` − `recvmsg timestamp`.  
   - This gives the **end-to-end enforcement time** for Docker updates, including userspace and kernel delays.

---

## Measuring Raw Cgroup Write Latency
To measure the latency of **direct kernel enforcement**, the framework bypasses `dockerd`:

1. **Identify the container's cgroup path:**  
   - Using the container PID, parse `/proc/[pid]/cgroup` to find the unified cgroup path.  

2. **Write directly to `memory.max` and `cpu.max`:**  
   - Use Python to open and write new limits into the cgroup files.  
   - No userspace daemon involved — writes go straight to the kernel.  

3. **Trace enforcement using eBPF:**  
   - Attach the same `vfs_write` kprobe to monitor enforcement latency.  
   - Record timestamps for each write and compute the latency.  

4. **Compare with Docker update:**  
   - Multiple iterations are performed to get reliable averages.  
   - The results demonstrate a massive speedup (~6,000× lower latency).

---

## Script Logic (`docker_cgroup_latency_comparison_2.py`)
The main Python script performs the following steps:

1. **Setup & Docker container creation:**  
   - Build a test image and run a container with host cgroup namespace.  

2. **Identify container and `dockerd` PIDs:**  
   - `get_container_pid()` finds the container's main process.  
   - `get_pid_by_name()` retrieves `dockerd` PID for eBPF tracing.  

3. **Attach eBPF probes:**  
   - Trace `dockerd` `recvmsg` entry points.  
   - Trace `vfs_write` for `memory.max` and `cpu.max`.  

4. **Measure Docker update latency:**  
   - Alternately change memory and CPU using `docker update`.  
   - Wait for eBPF `last_write_ts` to capture kernel enforcement timestamp.  
   - Record latencies across multiple iterations.  

5. **Measure raw cgroup write latency:**  
   - Directly open and write to cgroup files.  
   - Capture enforcement timestamps using eBPF.  
   - Compute average latencies.  

6. **Report results:**  
   - Average latency for Docker update (memory & CPU)  
   - Average latency for raw cgroup write  

7. **Cleanup:**  
   - Remove test container to avoid resource leaks.  

---

## Usage
**Requirements:**
- Linux with cgroups v2 enabled  
- Docker  
- Python 3 with `bcc` library  
- eBPF support (kernel ≥ 4.9 recommended)



**Run the script:**  
```bash
sudo python3 docker_cgroup_latency_comparison_2.py

## License
This project is licensed under the MIT License

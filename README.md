# 🚀 Real-Time Docker Resource Control Optimization Framework

A high-performance framework for real-time Docker resource management, achieving **~6,000× lower latency** than `docker update` by using direct cgroup v2 file writes. This project also introduces **nanosecond-level kernel latency tracing** for memory and CPU limit enforcement using **eBPF**, enabling deep observability into the Linux kernel's resource control behavior.

---

## 🧠 Motivation

Docker’s default `docker update` command introduces significant latency when modifying resource constraints at runtime. This framework:
- Bypasses the Docker daemon by writing directly to cgroup v2 files (e.g., `memory.max`, `cpu.max`)
- Uses **eBPF** to trace kernel enforcement timestamps at nanosecond precision
- Enables accurate benchmarking and analysis of resource enforcement behavior across thousands of iterations

---

## ✨ Key Features

- ⚡ **Ultra-Low-Latency Updates**  
  Direct cgroup file writes reduce latency from **26.7 ms → 0.004 ms**

- 🧠 **Nanosecond-Level Kernel Tracing with eBPF**  
  Tracks the exact kernel moment when memory/CPU limits are enforced via `vfs_write` kprobe

- 🧪 **Head-to-Head Benchmarking**  
  Compares `docker update` latency vs direct file-based updates under identical workloads

- 📊 **Statistical Analysis**  
  Benchmarks over **10,000 iterations** and reports average latencies for both strategies

---

## 📁 Project Structure

├── cgroup_latency_tracer.py # Direct cgroup v2 write benchmark + eBPF tracing
├── docker_latency_tracer.py # Docker CLI-based update benchmark + eBPF tracing
├── docker-test/
│ └── Dockerfile # Minimal container used for docker-based tests


---

## ⚙️ Requirements

- Linux with **cgroup v2** enabled
- **Docker** with `--cgroupns=host` support
- Python 3
- [BCC](https://github.com/iovisor/bcc) (`sudo apt install bpfcc-tools libbpfcc-dev python3-bcc`)

---

## 🧪 How to Run

### 1. Benchmark Direct Cgroup Writes (Low-Latency Path)
```bash
sudo python3 cgroup_latency_tracer.py

    Creates a cgroup under /sys/fs/cgroup/

    Alternates memory.max and cpu.max values

    Traces vfs_write timestamps for precise enforcement latency

2. Benchmark Docker Update Latency

sudo python3 docker_latency_tracer.py

    Builds a container image from ./docker-test/

    Runs the container with --cgroupns=host

    Uses docker update for resource changes

    Traces kernel-level enforcement timestamps via eBPF

📊 Sample Output

📊 Average memory.max latency via docker update: 26.723 ms
📊 Average memory.max latency via cgroup write:   0.004 ms
📊 Average cpu.max latency via docker update:    25.941 ms
📊 Average cpu.max latency via cgroup write:     0.003 ms

🔍 Novelty & Insights

This project is among the first to:

    Use eBPF to trace kernel-level resource enforcement latency

    Compare Docker vs native cgroup v2 file updates with such precision

    Quantify and visualize how container runtime abstraction impacts real-time control

📜 License

MIT
👨‍🔬 Author

Sambhav Singh
B.Tech, AI | NITK
GitHub: @Sambhav05-cmd

🚀 Real-Time Docker Resource Control Optimization Framework

A high-performance framework for real-time Docker resource management and kernel-level latency tracing, achieving ~6,000× lower latency than docker update by writing directly to cgroup v2 files. This system introduces nanosecond-resolution eBPF tracing to capture the precise moment when memory and CPU limits are enforced by the Linux kernel.

In addition to latency benchmarking, the project includes a flexible process control and monitoring framework that allows you to run workloads inside custom cgroups and plot real-time kernel metrics such as vmrss, pagefaults/sec, lru_isolate/sec, and page swaps/sec — all with minimal overhead using eBPF.
🧠 Motivation

Docker’s built-in docker update command introduces significant latency when modifying resource constraints at runtime. This framework addresses that by:

    Bypassing the Docker daemon and writing directly to cgroup v2 control files (e.g., memory.max, cpu.max)

    Tracing enforcement latency with nanosecond precision using eBPF (kprobe on vfs_write)

    Providing reproducible latency benchmarks across 10,000+ iterations

    Visualizing real-time system behavior under resource constraints

✨ Key Features
⚡ Ultra-Low-Latency Resource Updates

    Direct writes to cgroup files reduce update latency from 26.7 ms → 0.004 ms

🧠 Nanosecond-Level Kernel Tracing via eBPF

    Uses kprobe on vfs_write to track exact enforcement of memory and CPU limits
    NOTE : Same python write overhead is present in both cgroup write from python and docker update from python so the latency difference that is measured is not affected by python overhead.

🧪 Head-to-Head Latency Benchmarking

    Compares docker update vs direct file writes under identical measurement logic

📊 Statistical Analysis

    Benchmarks over 10,000 iterations

    Reports detailed average latencies for both update strategies

📁 Project Structure

├── cgroup_latency_tracer.py        # Direct cgroup write + eBPF latency trace
├── docker_latency_tracer.py        # Docker update benchmark + eBPF trace
├── monitor/
│   ├── process_runner.py           # Launches controlled workloads in cgroups
│   └── ebpf_plotter.py             # Real-time RSS, faults, swap plotting via BPF
├── docker-test/
│   └── Dockerfile                  # Lightweight test container for docker benchmarks

⚙️ Requirements

    Linux with cgroup v2 enabled

    Docker with --cgroupns=host support

    Python 3

    BCC / eBPF tools:

    sudo apt install bpfcc-tools libbpfcc-dev python3-bcc

🧪 How to Run
1. Benchmark Direct Cgroup Writes (Low-Latency Path)

sudo python3 cgroup_latency_tracer.py

    Writes to memory.max and cpu.max directly

    Traces kernel vfs_write to measure enforcement latency

2. Benchmark Docker Update Latency

sudo python3 docker_latency_tracer.py

    Runs a test container

    Modifies its limits via docker update

    Uses the same vfs_write tracing logic

📊 Sample Output

📊 Average memory.max latency via docker update: 26.723 ms
📊 Average memory.max latency via cgroup write:   0.004 ms
📊 Average cpu.max latency via docker update:    25.941 ms
📊 Average cpu.max latency via cgroup write:     0.003 ms

🔬 Extension: Real-Time Process Monitoring Framework

Beyond benchmarking, this repo includes a modular runtime controller that:

    Launches user-defined processes into custom cgroups

    Dynamically adjusts memory/CPU constraints

    Plots the following kernel metrics in real time:

        vmrss / (vmrss + vmswap)

        pagefaults/sec

        lru_isolate/sec

        pageswaps/sec

All graphs are powered by eBPF for low-overhead, high-frequency sampling, ideal for evaluating scheduling and memory policies in real workloads.
🔍 Novelty & Insights

This project is among the first to:

    Use eBPF to measure true kernel-level latency of resource enforcement

    Benchmark Docker vs native cgroup mechanisms with nanosecond granularity

    Provide a combined system for enforcement and observability in real time

    Quantify the hidden overhead of container abstraction layers

📜 License

MIT
👨‍🔬 Author

Sambhav Singh
B.Tech, Artificial Intelligence | NITK
GitHub: @Sambhav05-cmd

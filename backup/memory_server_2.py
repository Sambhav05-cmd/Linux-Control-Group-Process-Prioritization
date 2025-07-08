# memory_server.py
import socket
import mmap
import struct
import os
import matplotlib.pyplot as plt
import time
import threading

SHM_SIZE = 1024
# ready, blocked, swapped, running, faults, swaps, ratio
MEM_STRUCT = struct.Struct("d d d d Q Q d")

shm_map = {}
stats_history = {}

def handle_client(conn):
    shm_key = conn.recv(1024).decode().strip()
    conn.close()
    shm_path = "/dev/shm" + shm_key
    if not os.path.exists(shm_path): return
    fd = os.open(shm_path, os.O_RDONLY)
    mem = mmap.mmap(fd, SHM_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
    shm_map[shm_key] = mem
    stats_history[shm_key] = []

def plot():
    plt.ion()
    fig, axs = plt.subplots(3, 1, figsize=(10, 9))
    metrics = ["Page Faults/sec", "Swaps/sec", "VmRSS / (VmRSS + VmSwap)"]
    
    while True:
        time.sleep(0.4)
        for ax in axs: ax.cla()
        for shm_key, mem in shm_map.items():
            mem.seek(0)
            try:
                data = mem.read(MEM_STRUCT.size)
                unpacked = MEM_STRUCT.unpack(data)
                faults = unpacked[4]
                swaps = unpacked[5]
                ratio = unpacked[6]
                timestamp = time.time()

                stats_history[shm_key].append((timestamp, faults, swaps, ratio))
                h = stats_history[shm_key]
                if len(h) < 2: continue

                t = [x[0] for x in h[1:]]
                y_faults = [(h[i][1] - h[i-1][1]) / (h[i][0] - h[i-1][0]) if (h[i][0] - h[i-1][0]) > 0 else 0 for i in range(1, len(h))]
                y_swaps = [(h[i][2] - h[i-1][2]) / (h[i][0] - h[i-1][0]) if (h[i][0] - h[i-1][0]) > 0 else 0 for i in range(1, len(h))]
                y_ratio = [x[3] for x in h[1:]]

                axs[0].plot(t, y_faults, label=shm_key)
                axs[1].plot(t, y_swaps, label=shm_key)
                axs[2].plot(t, y_ratio, label=shm_key)

            except Exception as e:
                continue

        for i in range(3):
            axs[i].set_title(metrics[i])
            axs[i].legend(loc="upper right")
            axs[i].set_xlabel("Time (s)")
        plt.tight_layout()
        plt.pause(0.1)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9001))
server.listen(10)
threading.Thread(target=plot, daemon=True).start()
print("Memory Stats Server on port 9001")

while True:
    conn, _ = server.accept()
    threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


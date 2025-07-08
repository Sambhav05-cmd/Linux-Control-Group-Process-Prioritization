import socket
import mmap
import struct
import os
import matplotlib.pyplot as plt
import time
import threading

SHM_SIZE = 1024
MEM_STRUCT = struct.Struct("d d d d Q Q Q d")  # ready, blocked, swapped, running, faults, swaps, lru_isolates, ratio

shm_map = {}
stats_history = {}
initial_time = None

global_time = 0
time_lock = threading.Lock()

def handle_client(conn):
    global initial_time
    shm_key = conn.recv(1024).decode().strip()
    conn.close()
    shm_path = "/dev/shm" + shm_key
    if not os.path.exists(shm_path): return
    fd = os.open(shm_path, os.O_RDONLY)
    mem = mmap.mmap(fd, SHM_SIZE, mmap.MAP_SHARED, mmap.PROT_READ)
    shm_map[shm_key] = mem
    stats_history[shm_key] = []

    with time_lock:
        if initial_time is None:
            initial_time = time.time()

def plot():
    global global_time
    plt.ion()
    fig, axs = plt.subplots(4, 1, figsize=(10, 9))
    metrics = ["Page Faults/sec", "Swaps/sec", "lru_isolates/sec", "VmRSS / (VmRSS + VmSwap)"]
    
    while True:
        time.sleep(0.4)
        with time_lock:
            if initial_time is None:
                continue
            global_time = time.time() - initial_time

        for ax in axs:
            ax.cla()

        for shm_key, mem in shm_map.items():
            mem.seek(0)
            try:
                data = mem.read(MEM_STRUCT.size)
                unpacked = MEM_STRUCT.unpack(data)
                faults = unpacked[4]
                swaps = unpacked[5]
                lru = unpacked[6]
                ratio = unpacked[7]

                stats_history[shm_key].append((global_time, faults, swaps, lru, ratio))
                h = stats_history[shm_key]
                if len(h) < 2: continue

                t = [x[0] for x in h[1:]]
                y_faults = [(h[i][1] - h[i-1][1]) / (h[i][0] - h[i-1][0]) if (h[i][0] - h[i-1][0]) > 0 else 0 for i in range(1, len(h))]
                y_swaps = [(h[i][2] - h[i-1][2]) / (h[i][0] - h[i-1][0]) if (h[i][0] - h[i-1][0]) > 0 else 0 for i in range(1, len(h))]
                y_lru = [(h[i][3] - h[i-1][3]) / (h[i][0] - h[i-1][0]) if (h[i][0] - h[i-1][0]) > 0 else 0 for i in range(1, len(h))]
                y_ratio = [x[4] for x in h[1:]]

                axs[0].plot(t, y_faults, label=shm_key)
                axs[1].plot(t, y_swaps, label=shm_key)
                axs[2].plot(t, y_lru, label=shm_key)
                axs[3].plot(t, y_ratio, label=shm_key)

            except:
                continue

        for i in range(4):
            axs[i].set_title(metrics[i])
            axs[i].legend(loc="upper right")
            axs[i].set_xlabel("Time (s)")
            axs[i].set_ylim(bottom=0)
            
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


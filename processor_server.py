import socket
import mmap
import struct
import os
import matplotlib.pyplot as plt
import time
import threading

SHM_SIZE = 1024
PROC_STRUCT = struct.Struct("d d d d d")  # ready, blocked, swapped, running

shm_map = {}
stats_history = {}
initial_time = None  # Set when the first client connects

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

    # Initialize initial_time only once (when first client arrives)
    with time_lock:
        global initial_time
        if initial_time is None:
            initial_time = time.time()

def plot():
    global global_time
    plt.ion()
    fig, axs = plt.subplots(4, 1, figsize=(10, 8))
    metrics = ["ready", "blocked", "swapped", "running"]

    while True:
        time.sleep(0.4)
        with time_lock:
            if initial_time is None:
                continue  # Skip plotting if no client has connected yet
            global_time = time.time() - initial_time

        for ax in axs:
            ax.cla()

        for shm_key, mem in shm_map.items():
            mem.seek(0)
            try:
                data = mem.read(PROC_STRUCT.size)
                ready, blocked, swapped, running, _ = PROC_STRUCT.unpack(data)
                stats_history[shm_key].append((global_time, ready, blocked, swapped, running))
                h = stats_history[shm_key]
                if len(h) < 2: continue
                t = [x[0] for x in h[1:]]
                for i in range(4):
                    axs[i].plot(t, [x[i+1] for x in h[1:]], label=shm_key)
            except:
                continue

        for i in range(4):
            axs[i].set_title(metrics[i])
            axs[i].legend(loc="upper right")
            axs[i].set_ylim(0, 1)
        plt.tight_layout()
        plt.pause(0.1)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9000))
server.listen(10)
threading.Thread(target=plot, daemon=True).start()
print("Processor Stats Server on port 9000")

while True:
    conn, _ = server.accept()
    threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


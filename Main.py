import socket
import tkinter as tk
from tkinter import ttk
import threading
import time
import pydivert
import logging
import os
import json
import ctypes
import queue

# Logging setup
log_file = "firewall.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Configuration variables
PACKET_VOLUME_THRESHOLD = 100  # packets per 5 seconds
PACKET_WINDOW = 5  # seconds
PORT_SCAN_THRESHOLD = 20  # unique ports per 3 seconds
PORT_WINDOW = 3  # seconds
SUSPICIOUS_DURATION = 2  # seconds to be suspicious before blocking
BLOCKED_IPS_FILE = "blocked_ips.json"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log(f"Error loading blocked IPs: {e}")
    return []

def save_blocked_ips():
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f)
    except Exception as e:
        log(f"Error saving blocked IPs: {e}")

blocked_ips = load_blocked_ips()
running = False
packet_count = 0
attack_count = 0
ip_stats = {}
gui_queue = queue.Queue()

def process_gui_queue():
    try:
        while True:
            action, args = gui_queue.get_nowait()
            if action == "update_counter":
                counter_label.config(text=f"Packets: {args}")
            elif action == "update_attack":
                attack_label.config(text=f"Rule-based Attacks: {args}")
            elif action == "update_status":
                status_label.config(text=args)
            elif action == "add_blocked":
                listbox.insert(tk.END, args)
            elif action == "add_packet":
                tree.insert("", "end", values=args)
                if len(tree.get_children()) > 500:
                    tree.delete(tree.get_children()[0])
            elif action == "log":
                log_box.insert(tk.END, args + "\n")
                log_box.see(tk.END)
                if int(log_box.index('end-1c').split('.')[0]) > 1000:
                    log_box.delete('1.0', '2.0')
    except queue.Empty:
        pass
    root.after(100, process_gui_queue)


def get_local_addresses():
    addresses = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                addresses.add(addr)
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        addresses.update(host_ips)
    except Exception:
        pass
    return addresses

local_ips = get_local_addresses()


def is_trusted_packet(packet):
    if getattr(packet, "is_loopback", False):
        return True
    src = packet.src_addr
    dst = packet.dst_addr
    if src in local_ips or dst in local_ips:
        return True
    if src.startswith("127.") or dst.startswith("127."):
        return True
    return False

def add_ip():
    ip = entry_ip.get().strip()
    if ip:
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            gui_queue.put(("add_blocked", ip))
            save_blocked_ips()
            gui_queue.put(("log", f"Added manual block IP: {ip}"))
        entry_ip.delete(0, tk.END)


def detect_suspicious(packet):
    src = packet.src_addr
    dst_port = getattr(packet, "dst_port", 0) or 0
    now = time.time()

    stats = ip_stats.setdefault(src, {
        "timestamps": [],
        "port_times": {},
        "suspicious_since": None,
    })

    # Track packet volume in a 5-second window
    stats["timestamps"].append(now)
    while stats["timestamps"] and now - stats["timestamps"][0] > PACKET_WINDOW:
        stats["timestamps"].pop(0)
    packet_count_5s = len(stats["timestamps"])

    # Track unique destination ports in a 3-second window
    if dst_port:
        stats["port_times"][dst_port] = now
    for port, timestamp in list(stats["port_times"].items()):
        if now - timestamp > PORT_WINDOW:
            del stats["port_times"][port]
    unique_ports_3s = len(stats["port_times"])

    suspicious = packet_count_5s > PACKET_VOLUME_THRESHOLD or unique_ports_3s > PORT_SCAN_THRESHOLD
    if suspicious:
        if stats["suspicious_since"] is None:
            stats["suspicious_since"] = now
    else:
        stats["suspicious_since"] = None

    should_block = False
    if stats["suspicious_since"] is not None and now - stats["suspicious_since"] >= SUSPICIOUS_DURATION:
        should_block = True

    return suspicious, should_block, packet_count_5s, unique_ports_3s

def remove_ip():
    selected = listbox.curselection()
    if selected:
        ip = listbox.get(selected)
        blocked_ips.remove(ip)
        listbox.delete(selected)
        save_blocked_ips()
        gui_queue.put(("log", f"Removed blocked IP: {ip}"))

def start_firewall():
    if not is_admin():
        gui_queue.put(("update_status", "Status: Need Admin Rights"))
        gui_queue.put(("log", "Firewall requires administrator privileges to capture packets"))
        return

    global running, packet_count, attack_count
    running = True
    packet_count = 0
    attack_count = 0
    gui_queue.put(("update_counter", "Packets: 0"))
    gui_queue.put(("update_attack", "Rule-based Attacks: 0"))
    gui_queue.put(("update_status", "Status: Running"))
    gui_queue.put(("log", "Vabby Firewall Started with rule-based detection"))

    def run():
        global packet_count, attack_count
        total_packets = 0
        try:
            with pydivert.WinDivert("ip") as w:
                for packet in w:
                    total_packets += 1
                    if total_packets % 100 == 0:
                        gui_queue.put(("log", f"Processed {total_packets} packets"))
                    if not running:
                        break

                    try:
                        if not hasattr(packet, 'src_addr'):
                            w.send(packet)
                            continue
                        src = packet.src_addr
                        dst = packet.dst_addr
                        proto = str(packet.protocol)
                        sport = getattr(packet, 'src_port', '')
                        dport = getattr(packet, 'dst_port', '')

                        # Add all packets to dashboard
                        gui_queue.put(("add_packet", (f"{src}:{sport}", f"{dst}:{dport}", proto)))

                        # Update counter for all packets
                        packet_count += 1
                        if packet_count % 10 == 0:
                            gui_queue.put(("update_counter", f"Packets: {packet_count}"))

                        # Manual block list should override trusted traffic bypass
                        if src in blocked_ips or dst in blocked_ips:
                            blocked_ip = src if src in blocked_ips else dst
                            gui_queue.put(("update_status", f"Blocked IP: {blocked_ip}"))
                            gui_queue.put(("log", f"Blocked: {blocked_ip}"))
                            continue

                        if is_trusted_packet(packet):
                            gui_queue.put(("update_status", "Trusted local traffic ignored"))
                            w.send(packet)
                            continue

                        # Rule-based detection
                        suspicious, should_block, volume, scan_ports = detect_suspicious(packet)
                        if suspicious:
                            attack_count += 1
                            gui_queue.put(("update_attack", f"Rule-based Attacks: {attack_count}"))
                            if should_block and auto_block_var.get() and src not in blocked_ips:
                                blocked_ips.append(src)
                                gui_queue.put(("add_blocked", src))
                                save_blocked_ips()
                                gui_queue.put(("update_status", f"Blocked suspicious IP: {src}"))
                                gui_queue.put(("log", f"Rule-based automatically blocked {src}: {volume} packets/5s, {scan_ports} ports/3s"))
                                continue
                            gui_queue.put(("update_status", f"Suspicious detected: {src}"))
                            gui_queue.put(("log", f"Suspicious behavior from {src}: {volume} packets/5s, {scan_ports} ports/3s"))
                            w.send(packet)
                            continue

                        # Search filter
                        search = search_var.get()
                        if search and search not in src and search not in dst:
                            w.send(packet)
                            continue

                        # Protocol filter
                        selected = protocol_var.get()
                        if selected != "ALL" and selected not in proto:
                            w.send(packet)
                            continue

                        w.send(packet)
                    except Exception as e:
                        gui_queue.put(("log", f"Error processing packet: {e}"))
                        continue
        except Exception as e:
            gui_queue.put(("log", f"Error starting firewall: {e}"))
            gui_queue.put(("update_status", "Status: Error"))

    threading.Thread(target=run, daemon=True).start()

def stop_firewall():
    global running
    running = False
    gui_queue.put(("update_status", "Status: Stopped"))
    gui_queue.put(("log", "Firewall Stopped"))

def log(msg):
    gui_queue.put(("log", msg))
    logging.info(msg)

# ---------------- GUI ----------------
root = tk.Tk()
root.title("🔥 Vabby Firewall Dashboard")
root.geometry("1000x650")
root.configure(bg="#1e1e1e")

# Style
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
                background="#1e1e1e",
                foreground="white",
                fieldbackground="#1e1e1e")
style.map('Treeview', background=[('selected', '#007acc')])

# Top Frame
top_frame = tk.Frame(root, bg="#1e1e1e")
top_frame.pack(fill="x")

entry_ip = tk.Entry(top_frame)
entry_ip.pack(side="left", padx=10, pady=10)

tk.Button(top_frame, text="Add IP", command=add_ip, bg="green").pack(side="left")
tk.Button(top_frame, text="Remove IP", command=remove_ip, bg="red").pack(side="left")

# Protocol filter
protocol_var = tk.StringVar(value="ALL")
protocol_menu = ttk.Combobox(top_frame, textvariable=protocol_var, width=10)
protocol_menu['values'] = ("ALL", "TCP", "UDP")
protocol_menu.pack(side="left", padx=10)

# Search
search_var = tk.StringVar()
search_entry = tk.Entry(top_frame, textvariable=search_var)
search_entry.pack(side="left", padx=10)

# Rule-based auto-block option
auto_block_var = tk.BooleanVar(value=True)
auto_block_checkbox = tk.Checkbutton(top_frame, text="Auto-block suspicious IP", variable=auto_block_var, fg="white", bg="#1e1e1e", selectcolor="#1e1e1e", activebackground="#1e1e1e", activeforeground="white")
auto_block_checkbox.pack(side="left", padx=10)

# Buttons
tk.Button(top_frame, text="Start", command=start_firewall, bg="green").pack(side="right", padx=10)
tk.Button(top_frame, text="Stop", command=stop_firewall, bg="red").pack(side="right")

# Counter
counter_label = tk.Label(top_frame, text="Packets: 0", fg="white", bg="#1e1e1e")
counter_label.pack(side="right")

attack_label = tk.Label(top_frame, text="Rule-based Attacks: 0", fg="white", bg="#1e1e1e")
attack_label.pack(side="right", padx=10)

status_label = tk.Label(top_frame, text="Status: Idle", fg="white", bg="#1e1e1e")
status_label.pack(side="right", padx=10)

# Main Frame
main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(fill="both", expand=True)

# Left Panel
left_frame = tk.Frame(main_frame, bg="#2d2d2d", width=200)
left_frame.pack(side="left", fill="y")

tk.Label(left_frame, text="Blocked IPs", fg="white", bg="#2d2d2d").pack()

listbox = tk.Listbox(left_frame, bg="#1e1e1e", fg="white")
listbox.pack(fill="both", expand=True, padx=5, pady=5)

# Load blocked IPs into listbox
for ip in blocked_ips:
    listbox.insert(tk.END, ip)

right_frame = tk.Frame(main_frame, bg="#1e1e1e")
right_frame.pack(side="right", fill="both", expand=True)

# Show ports in the table
columns = ("Source IP:Port", "Destination IP:Port", "Protocol")
tree = ttk.Treeview(right_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
tree.pack(fill="both", expand=True)
tree.pack(fill="both", expand=True)

# Log box
log_box = tk.Text(root, height=6, bg="black", fg="lime")
log_box.pack(fill="x")

# Start processing GUI queue
process_gui_queue()

root.mainloop()

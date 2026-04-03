from collections import defaultdict

syn_count = defaultdict(int)
port_scan = defaultdict(set)

THRESHOLD_SYN = 20
THRESHOLD_PORT = 10

def detect_signature(packet):
    alerts = []

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src

        if packet.haslayer("TCP"):
            flags = packet["TCP"].flags

            # SYN Flood detection
            if flags == "S":
                syn_count[src_ip] += 1
                if syn_count[src_ip] > THRESHOLD_SYN:
                    alerts.append(f"SYN Flood detected from {src_ip}")

            # Port scan detection
            dport = packet["TCP"].dport
            port_scan[src_ip].add(dport)

            if len(port_scan[src_ip]) > THRESHOLD_PORT:
                alerts.append(f"Port Scan detected from {src_ip}")

    return alerts
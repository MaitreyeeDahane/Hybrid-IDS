from collections import defaultdict
import time

packet_count = defaultdict(int)
start_time = time.time()

THRESHOLD_RATE = 50
INTERVAL = 5

def detect_anomaly(packet):
    global start_time
    alerts = []

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        packet_count[src_ip] += 1

    current_time = time.time()

    if current_time - start_time > INTERVAL:
        for ip, count in packet_count.items():
            if count > THRESHOLD_RATE:
                alerts.append(f"Anomaly detected: High traffic from {ip}")

        packet_count.clear()
        start_time = current_time

    return alerts
from scapy.all import sniff
from signature import detect_signature
from anomaly import detect_anomaly
import datetime

packet_counter = 0

# INFO message (blue)
def log_info(msg):
    print(f"\033[94m[INFO]\033[0m {msg}")

# ALERT message (red)
def log_alert(msg):
    print(f"\033[91m[ALERT]\033[0m {msg}")

def process_packet(packet):
    global packet_counter
    packet_counter += 1

    sig_alerts = detect_signature(packet)
    ano_alerts = detect_anomaly(packet)

    # Show alerts
    for alert in sig_alerts + ano_alerts:
        log_alert(alert)

        # Save with timestamp
        with open("alerts.log", "a") as f:
            f.write(f"{datetime.datetime.now()} - {alert}\n")

    # Show packet processing info every 20 packets
    if packet_counter % 20 == 0:
        print(f"\033[93m[INFO]\033[0m Processed {packet_counter} packets")

# Start message
log_info("Starting Hybrid IDS... Press Ctrl+C to stop.")

# Start sniffing
sniff(prn=process_packet, store=0)
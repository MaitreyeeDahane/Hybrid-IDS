from scapy.all import sniff
from signature import detect_signature
from anomaly import detect_anomaly

def process_packet(packet):
    sig_alerts = detect_signature(packet)
    ano_alerts = detect_anomaly(packet)

    for alert in sig_alerts + ano_alerts:
        print(f"[ALERT] {alert}")
        with open("alerts.log", "a") as f:
            f.write(alert + "\n")

print("Starting Hybrid IDS... Press Ctrl+C to stop.")

sniff(prn=process_packet, store=0)
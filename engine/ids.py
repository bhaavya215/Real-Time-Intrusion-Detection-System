from scapy.all import sniff, IP, TCP
import datetime
import os
import json
import sys
import threading
import time

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rules.syn_scan import load_rules  # Import rule-loading function

# Define log file path
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'alerts.ndjson')  # Using NDJSON format
ALERT_THRESHOLD = 5  # Max SYN packets from one IP in a short time
COOLDOWN_SECONDS = 30  # Time before the same IP can be alerted again
DECAY_INTERVAL = 10  # How often to decay SYN count
DECAY_AMOUNT = 1  # How much to decay per interval

syn_tracker = {}
last_alert_time = {}

def initialize_logs():
    """Create logs directory and initialize log file if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("")  # initialize empty NDJSON file

def log_alert(ip, count, rule_type="SYN Flood Attempt"):
    """Log an alert to the NDJSON file."""
    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": rule_type,
        "ip": ip,
        "syn_count": count
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(alert) + "\n")

    print(f"[ALERT] {rule_type} from {ip} ({count} packets)")

def decay_syn_counts():
    """Background thread to decay SYN counters over time."""
    while True:
        time.sleep(DECAY_INTERVAL)
        for ip in list(syn_tracker):
            syn_tracker[ip] = max(0, syn_tracker[ip] - DECAY_AMOUNT)

def detect_packet(pkt):
    """Detect suspicious packets based on loaded rules."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src

        if pkt[TCP].flags == 'S':  # Check for SYN flag
            syn_tracker[src_ip] = syn_tracker.get(src_ip, 0) + 1

            # Check cooldown to avoid duplicate alerts
            now = datetime.datetime.now()
            last_alert = last_alert_time.get(src_ip)
            should_alert = (
                syn_tracker[src_ip] > ALERT_THRESHOLD and
                (not last_alert or (now - last_alert).total_seconds() > COOLDOWN_SECONDS)
            )

            if should_alert:
                log_alert(src_ip, syn_tracker[src_ip])
                last_alert_time[src_ip] = now
                syn_tracker[src_ip] = 0  # Reset after alert

        # Apply additional rules
        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker)

def start_sniffing():
    """Start packet sniffing with cleanup on exit."""
    print("[+] Sniffing started... Press Ctrl+C to stop.")
    try:
        decay_thread = threading.Thread(target=decay_syn_counts, daemon=True)
        decay_thread.start()
        sniff(filter="tcp", prn=detect_packet, store=0)
    except KeyboardInterrupt:
        print("\n[-] Sniffing stopped by user.")
    finally:
        syn_tracker.clear()
        print("[-] Tracker cleared. IDS shutting down.")

if __name__ == '__main__':
    initialize_logs()
    start_sniffing()

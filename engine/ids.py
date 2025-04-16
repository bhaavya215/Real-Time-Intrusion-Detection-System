from scapy.all import sniff, IP, TCP
import datetime
import os
import json
import sys

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rules.syn_scan import load_rules  # Import rule-loading function

# Define log file path
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'alerts.json')
alert_threshold = 5  # Max SYN packets from one IP in a short time
syn_tracker = {}

def initialize_logs():
    """Create logs directory and initialize log file if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write('[]\n')  # Initialize as JSON array

def log_alert(ip, count, rule_type="SYN Flood Attempt"):
    """Log an alert to the JSON file."""
    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": rule_type,
        "ip": ip,
        "syn_count": count
    }
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {rule_type} from {ip} ({count} packets)")

def detect_packet(pkt):
    """Detect suspicious packets based on loaded rules."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'S':  # Check for SYN flag
            syn_tracker[src_ip] = syn_tracker.get(src_ip, 0) + 1
            if syn_tracker[src_ip] > alert_threshold:
                log_alert(src_ip, syn_tracker[src_ip])
                syn_tracker[src_ip] = 0  # Reset counter after alert
        # Extend with additional rule checks
        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker)

def start_sniffing():
    """Start packet sniffing with cleanup on exit."""
    print("[+] Sniffing started... Press Ctrl+C to stop.")
    try:
        sniff(filter="tcp", prn=detect_packet, store=0)
    except KeyboardInterrupt:
        print("\n[-] Sniffing stopped by user.")
    finally:
        syn_tracker.clear()  # Cleanup tracker on exit

if __name__ == '__main__':
    initialize_logs()
    start_sniffing()
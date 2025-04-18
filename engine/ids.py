from scapy.all import sniff, IP, TCP
import datetime
import os
import json
import sys
import threading
import time

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from engine.rules import load_rules  
try:
    from engine.rules import load_rules  # or specific scan files
    # print("Import successful!")
except ImportError as e:
    print(f"Error importing rules: {e}")
    sys.exit(1)


# Constants
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'alerts.json')
alert_threshold = 5  # Basic threshold (may be used for native logic)
DECAY_INTERVAL = 10  # seconds
DECAY_AMOUNT = 2

# Global tracker
syn_tracker = {
    'syn_flood': {},  # Tracker for SYN flood
    'port_scan': {},  # Tracker for port scan
    'icmp_flood': {},
    'udp_flood': {},
    'tcp_rst_flood': {}
}

def initialize_logs():
    """Create logs directory and initialize log file if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)  # initialize as empty JSON array

def log_alert(ip, count, rule_type="SYN Flood Attempt"):
    """Log an alert to the JSON file in proper JSON array format."""
    # Read existing logs
    with open(LOG_FILE, 'r') as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            logs = []

    # Append new alert
    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": rule_type,
        "ip": ip,
        "count": count
    }
    logs.append(alert)

    # Write the updated list back to the file
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

    print(f"[ALERT] {rule_type} from {ip} ({count} packets)")

def detect_packet(pkt):
    """Detect suspicious packets based on loaded rules."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        
        if src_ip == "192.168.0.169":  # Skip your own IP
            return
        
        if pkt[TCP].flags == 'S':  # Check for SYN flag
            syn_tracker[src_ip] = syn_tracker.get(src_ip, 0) + 1
            if syn_tracker[src_ip] > alert_threshold:
                log_alert(src_ip, syn_tracker[src_ip])
                syn_tracker[src_ip] = 0  # Reset counter after alert
        
        # Apply all rules from loaded modules dynamically
        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker)


def decay_syn_counts():
    """Periodically decay SYN counts to avoid stale alerts."""
    while True:
        time.sleep(DECAY_INTERVAL)
        if 'syn_flood' in syn_tracker:
            for ip in list(syn_tracker['syn_flood'].keys()):
                syn_tracker['syn_flood'][ip] = max(0, syn_tracker['syn_flood'][ip] - DECAY_AMOUNT)

def start_sniffing():
    """Start packet sniffing with cleanup on exit."""
    print("[+] Sniffing started... Press Ctrl+C to stop.")

    # Start decay thread for syn flood
    decay_thread = threading.Thread(target=decay_syn_counts, daemon=True)
    decay_thread.start()

    try:
        sniff(filter="ip", prn=detect_packet, store=0)  # Can use interface='eth0'
    except KeyboardInterrupt:
        print("\n[-] Sniffing stopped by user.")
    finally:
        syn_tracker.clear()

if __name__ == '__main__':
    initialize_logs()
    start_sniffing()

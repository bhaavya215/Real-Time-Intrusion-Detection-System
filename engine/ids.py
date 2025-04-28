from scapy.all import sniff, IP, TCP
import datetime
import os
import json
import sys
import threading
import time

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Assume rules.py will be provided later
try:
    from engine.rules import load_rules
except ImportError as e:
    print(f"Error importing rules: {e}")
    sys.exit(1)

# Constants
LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
LOG_FILE = os.path.join(LOG_DIR, 'alerts.json')
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), 'blocked_ips.json')
DECAY_INTERVAL = 10  # seconds
DECAY_AMOUNT = 2

# Global state
running = False
syn_tracker = {
    'syn_flood': {},
    'port_scan': {},
    'icmp_flood': {},
    'udp_flood': {},
    'tcp_rst_flood': {}
}
blocked_ips = set()  # To sync with /blocked-ips API

def initialize_logs():
    """Create logs directory and initialize log file if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)  # Initialize as empty JSON array

def update_blocked_ips():
    """Periodically update the blocked_ips set from the JSON file."""
    global blocked_ips
    while True:
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    blocked_ips_data = json.load(f)
                    if isinstance(blocked_ips_data, list):
                        blocked_ips = set(blocked_ips_data)
                    else:
                        blocked_ips = set()
            except json.JSONDecodeError:
                print("Error parsing blocked_ips.json, resetting to empty set")
                blocked_ips = set()
        time.sleep(5)  # Update every 5 seconds

def log_alert(ip, count, rule_type="SYN Flood Attempt"):
    """Log an alert to the JSON file in proper JSON array format."""
    if ip in blocked_ips:
        return  # Skip logging for blocked IPs

    with open(LOG_FILE, 'r') as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            logs = []

    alert = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": rule_type,
        "ip": ip,
        "count": count
    }
    logs.append(alert)

    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

    print(f"[ALERT] {rule_type} from {ip} ({count} packets)")

def detect_packet(pkt):
    """Detect suspicious packets based on loaded rules."""
    if not running:
        return

    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        
        if src_ip in blocked_ips or src_ip == "192.168.0.169":  # Skip your own IP or blocked IPs
            return

        if pkt[TCP].flags == 'S':  # Check for SYN flag
            syn_tracker.setdefault(src_ip, 0)
            syn_tracker[src_ip] += 1
            if syn_tracker[src_ip] > 5:  # Use dynamic threshold from rules later
                log_alert(src_ip, syn_tracker[src_ip])
                syn_tracker[src_ip] = 0  # Reset counter after alert

        # Apply all rules from loaded modules dynamically
        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker, blocked_ips)

def decay_syn_counts():
    """Periodically decay SYN counts to avoid stale alerts."""
    while running:
        time.sleep(DECAY_INTERVAL)
        for ip in list(syn_tracker.keys()):
            syn_tracker[ip] = max(0, syn_tracker[ip] - DECAY_AMOUNT)

def start_sniffing():
    """Start packet sniffing."""
    global running
    running = True
    print("[+] Sniffing started...")

    # Start decay thread
    decay_thread = threading.Thread(target=decay_syn_counts, daemon=True)
    decay_thread.start()

    # Start blocked IPs update thread
    blocked_ips_thread = threading.Thread(target=update_blocked_ips, daemon=True)
    blocked_ips_thread.start()

    try:
        sniff(filter="ip", prn=detect_packet, store=0)
    except Exception as e:
        print(f"[-] Sniffing error: {e}")
    finally:
        running = False
        syn_tracker.clear()

def stop_sniffing():
    """Stop packet sniffing."""
    global running
    running = False
    print("[-] Sniffing stopped.")

if __name__ == "__main__":
    initialize_logs()
    # Run sniffing directly if not controlled by API
    start_sniffing()
else:
    # Expose functions for API control
    __all__ = ['start_sniffing', 'stop_sniffing', 'log_alert', 'blocked_ips']
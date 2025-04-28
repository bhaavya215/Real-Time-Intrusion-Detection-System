from scapy.all import sniff, IP, TCP, get_if_list
import datetime
import os
import json
import sys
import threading
import time
import requests
import signal

# Add engine directory to sys.path to resolve import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
API_URL = "http://localhost:3000/rules"  # Express API for rules
LOG_INTERVAL = 5  # seconds for packet logging

# Global state
running = False
syn_tracker = {
    'syn_flood': {},
    'port_scan': {},
    'icmp_flood': {},
    'udp_flood': {},
    'tcp_rst_flood': {},
    'ack_scan': {},
    'syn_ack_scan': {},
    'xmas_scan': {}
}
blocked_ips = set()
thresholds = {}
packet_count = 0
packet_lock = threading.Lock()

def signal_handler(sig, frame):
    """Handle SIGTERM for graceful shutdown."""
    print("[-] Received SIGTERM, stopping IDS...")
    stop_sniffing()
    sys.exit(0)

def initialize_logs():
    """Create logs directory and initialize log file if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)

def fetch_thresholds():
    """Fetch rule thresholds from the Express API."""
    global thresholds
    try:
        response = requests.get(API_URL)
        rules = response.json().get('rules', [])
        for rule in rules:
            thresholds[rule['type']] = rule['threshold']
    except Exception as e:
        print(f"Error fetching thresholds from API: {e}")
        thresholds.update({
            'SYN_FLOOD': 10,
            'PORT_SCAN': 15,
            'ICMP_FLOOD': 50,
            'TCP_RST_FLOOD': 20,
            'UDP_FLOOD': 30,
            'ACK_SCAN': 20,
            'SYN_ACK_SCAN': 10,
            'XMAS_SCAN': 5
        })

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
        time.sleep(5)

def log_alert(ip, count, rule_type="SYN Flood Attempt"):
    """Log an alert to the JSON file in proper JSON array format."""
    if ip in blocked_ips:
        return

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

def decay_counts():
    """Periodically decay counts for all attack types to avoid stale alerts."""
    while running:
        time.sleep(DECAY_INTERVAL)
        for attack_type in syn_tracker.keys():
            tracker = syn_tracker[attack_type]
            if attack_type == 'port_scan':
                for ip in list(tracker.keys()):
                    if len(tracker[ip]) > 0:
                        tracker[ip] = set()
            else:
                for ip in list(tracker.keys()):
                    tracker[ip] = max(0, tracker[ip] - DECAY_AMOUNT)

def log_packet_stats():
    """Log packet count and intrusions every interval."""
    global packet_count
    last_alerts = []
    while running:
        time.sleep(LOG_INTERVAL)
        with packet_lock:
            current_count = packet_count
            packet_count = 0
        with open(LOG_FILE, 'r') as f:
            try:
                logs = json.load(f)
                last_interval = datetime.datetime.now() - datetime.timedelta(seconds=LOG_INTERVAL)
                last_alerts = [log for log in logs[-10:] if log["timestamp"] >= last_interval.isoformat()]
            except (json.JSONDecodeError, KeyError):
                last_alerts = []
        print(f"[STATS] Packets detected in last {LOG_INTERVAL} seconds: {current_count}, Intrusions: {len(last_alerts)} - {last_alerts}")

def detect_packet(pkt):
    """Detect suspicious packets based on loaded rules."""
    if not running:
        return

    if IP in pkt:
        with packet_lock:
            global packet_count
            packet_count += 1

        src_ip = pkt[IP].src
        
        if src_ip in blocked_ips:
            return

        for rule_func in load_rules():
            rule_func(pkt, log_alert, syn_tracker, thresholds)

def start_sniffing():
    """Start packet sniffing on all available interfaces."""
    global running
    running = True
    print("[+] Sniffing started on all interfaces...")

    # Fetch thresholds from API
    fetch_thresholds()

    # Start decay thread
    decay_thread = threading.Thread(target=decay_counts, daemon=True)
    decay_thread.start()

    # Start blocked IPs update thread
    blocked_ips_thread = threading.Thread(target=update_blocked_ips, daemon=True)
    blocked_ips_thread.start()

    # Start packet stats logging thread
    stats_thread = threading.Thread(target=log_packet_stats, daemon=True)
    stats_thread.start()

    # Get all available interfaces
    interfaces = get_if_list()  # List all interfaces

    try:
        # Start sniffing on all interfaces
        sniff(iface=interfaces, filter="ip", prn=detect_packet, store=0)
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
    # Register signal handler for SIGTERM
    signal.signal(signal.SIGTERM, signal_handler)
    initialize_logs()
    start_sniffing()
else:
    __all__ = ['start_sniffing', 'stop_sniffing', 'log_alert', 'blocked_ips']
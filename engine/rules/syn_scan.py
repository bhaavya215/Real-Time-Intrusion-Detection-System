from scapy.all import IP, TCP, UDP, ICMP
import datetime

# Cooldown window for each rule (in seconds)
COOLDOWNS = {
    "SYN Flood Attack": 30,
    "Port Scan Detected": 60,
    "ICMP Flood Attack": 60,
    "TCP RST Flood Attack": 45,
    "UDP Flood Attack": 45,
}

# Global state for cooldown tracking
last_alert_time = {}

def is_on_cooldown(ip, rule_type):
    """Check if the given IP is in cooldown for the specific rule."""
    now = datetime.datetime.now()
    last_time = last_alert_time.get((ip, rule_type))
    if last_time and (now - last_time).total_seconds() < COOLDOWNS[rule_type]:
        return True
    last_alert_time[(ip, rule_type)] = now
    return False

def check_syn_flood(pkt, log_alert, tracker):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src
        syn_count = tracker.setdefault('syn_flood', {}).setdefault(src_ip, 0)
        tracker['syn_flood'][src_ip] = syn_count + 1
        if tracker['syn_flood'][src_ip] > 10:
            if not is_on_cooldown(src_ip, "SYN Flood Attack"):
                log_alert(src_ip, tracker['syn_flood'][src_ip], "SYN Flood Attack")
            tracker['syn_flood'][src_ip] = 0

def check_port_scan(pkt, log_alert, tracker):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        now = datetime.datetime.now()

        port_tracker = tracker.setdefault('port_scan', {}).setdefault(src_ip, {})
        port_tracker[dst_port] = now

        # Remove ports older than 30 seconds
        recent_ports = {
            port: ts for port, ts in port_tracker.items()
            if (now - ts).total_seconds() < 30
        }
        tracker['port_scan'][src_ip] = recent_ports

        if len(recent_ports) > 15:
            if not is_on_cooldown(src_ip, "Port Scan Detected"):
                log_alert(src_ip, len(recent_ports), "Port Scan Detected")
            tracker['port_scan'][src_ip] = {}

def check_icmp_flood(pkt, log_alert, tracker):
    if IP in pkt and ICMP in pkt:
        src_ip = pkt[IP].src
        icmp_count = tracker.setdefault('icmp_flood', {}).setdefault(src_ip, 0)
        tracker['icmp_flood'][src_ip] = icmp_count + 1
        if tracker['icmp_flood'][src_ip] > 50:
            if not is_on_cooldown(src_ip, "ICMP Flood Attack"):
                log_alert(src_ip, tracker['icmp_flood'][src_ip], "ICMP Flood Attack")
            tracker['icmp_flood'][src_ip] = 0

def check_tcp_rst_attack(pkt, log_alert, tracker):
    if IP in pkt and TCP in pkt and pkt[TCP].flags == 'R':
        src_ip = pkt[IP].src
        rst_count = tracker.setdefault('rst_flood', {}).setdefault(src_ip, 0)
        tracker['rst_flood'][src_ip] = rst_count + 1
        if tracker['rst_flood'][src_ip] > 20:
            if not is_on_cooldown(src_ip, "TCP RST Flood Attack"):
                log_alert(src_ip, tracker['rst_flood'][src_ip], "TCP RST Flood Attack")
            tracker['rst_flood'][src_ip] = 0

def check_udp_flood(pkt, log_alert, tracker):
    if IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        udp_count = tracker.setdefault('udp_flood', {}).setdefault(src_ip, 0)
        tracker['udp_flood'][src_ip] = udp_count + 1
        if tracker['udp_flood'][src_ip] > 30:
            if not is_on_cooldown(src_ip, "UDP Flood Attack"):
                log_alert(src_ip, tracker['udp_flood'][src_ip], "UDP Flood Attack")
            tracker['udp_flood'][src_ip] = 0

def load_rules():
    """Return list of rule functions to apply."""
    return [
        check_syn_flood,
        check_port_scan,
        check_icmp_flood,
        check_tcp_rst_attack,
        check_udp_flood
    ]

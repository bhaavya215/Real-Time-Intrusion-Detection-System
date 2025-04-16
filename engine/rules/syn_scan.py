from scapy.all import IP, TCP

def check_syn_scan(pkt, log_alert, tracker):
    """Detect potential SYN scan patterns based on repeated SYN packets."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'S' and tracker.get(src_ip, 0) > 3:
            log_alert(src_ip, tracker[src_ip], "Potential SYN Scan")

def check_port_scan(pkt, log_alert, tracker):
    """Detect potential port scan by tracking unique destination ports from one IP."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        port_tracker = getattr(tracker, 'port_scan', {})
        port_tracker.setdefault(src_ip, set()).add(dst_port)
        if len(port_tracker[src_ip]) > 10:  # Threshold for unique ports
            log_alert(src_ip, len(port_tracker[src_ip]), "Potential Port Scan")
            port_tracker[src_ip].clear()  # Reset after alert
        tracker.port_scan = port_tracker

def load_rules():
    """Return list of rule functions to apply."""
    return [check_syn_scan, check_port_scan]
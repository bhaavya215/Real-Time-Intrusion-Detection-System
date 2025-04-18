from scapy.all import IP, TCP, UDP, ICMP
#kdd 99
def check_syn_flood(pkt, log_alert, tracker):
    """Detect SYN flood attacks by excessive SYN packets from one IP."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        tracker.setdefault(src_ip, 0)
        if pkt[TCP].flags == 'S':
            tracker[src_ip] += 1
            if tracker[src_ip] > 10:  # Threshold for SYN flood
                log_alert(src_ip, tracker[src_ip], "SYN Flood Attack")
                tracker[src_ip] = 0  # Reset after alert

def check_port_scan(pkt, log_alert, tracker):
    """Detect port scans by tracking unique destination ports."""
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        port_tracker = tracker.setdefault('port_scan', {})
        port_tracker.setdefault(src_ip, set()).add(dst_port)
        if len(port_tracker[src_ip]) > 15:  # Threshold for port scan
            log_alert(src_ip, len(port_tracker[src_ip]), "Port Scan Detected")
            port_tracker[src_ip].clear()  # Reset after alert

def check_icmp_flood(pkt, log_alert, tracker):
    """Detect ICMP flood attacks by excessive ICMP packets."""
    if IP in pkt and ICMP in pkt:
        src_ip = pkt[IP].src
        tracker.setdefault(src_ip, 0)
        tracker[src_ip] += 1
        if tracker[src_ip] > 50:  # Threshold for ICMP flood
            log_alert(src_ip, tracker[src_ip], "ICMP Flood Attack")
            tracker[src_ip] = 0  # Reset after alert

def check_tcp_rst_attack(pkt, log_alert, tracker):
    """Detect TCP RST flood attacks by excessive RST packets."""
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        if pkt[TCP].flags == 'R':
            tracker.setdefault(src_ip, 0)
            tracker[src_ip] += 1
            if tracker[src_ip] > 20:  # Threshold for RST flood
                log_alert(src_ip, tracker[src_ip], "TCP RST Flood Attack")
                tracker[src_ip] = 0  # Reset after alert

def check_udp_flood(pkt, log_alert, tracker):
    """Detect UDP flood attacks by excessive UDP packets."""
    if IP in pkt and UDP in pkt:
        src_ip = pkt[IP].src
        tracker.setdefault(src_ip, 0)
        tracker[src_ip] += 1
        if tracker[src_ip] > 30:  # Threshold for UDP flood
            log_alert(src_ip, tracker[src_ip], "UDP Flood Attack")
            tracker[src_ip] = 0  # Reset after alert

def load_rules():
    """Return list of rule functions to apply."""
    return [check_syn_flood, check_port_scan, check_icmp_flood, check_tcp_rst_attack, check_udp_flood]
import subprocess
import json
import logging
from logging.handlers import RotatingFileHandler
from tqdm import tqdm
import nmap
import socket
from email.mime.text import MIMEText
import smtplib
from scapy.all import IP, TCP, Raw, sniff, wrpcap
import time
import re
import os

from_email = os.getenv('FROM_EMAIL')
from_password = os.getenv('FROM_EMAIL_PASSWORD')

NMAP_SCAN_OPTIONS = [
    "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sP", "-sO", "-sA", "-O", "-sV", "-p", "-T", "-F", "-d", "-v", "--version-light", "--version-intensity", "--osscan-limit", "--osscan-guess", "--max-retries", "--max-scan-delay", "--defeat-rst-ratelimit", "--defeat-icmp-ratelimit", "--reason", "--packet-trace"
]

def validate_ip(ip):
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

connections = {}
open_ports_info = []
devices = []
email_alerts = []

def setup_logging(log_level):
    logger = logging.getLogger()
    
    if not logger.handlers:
        logger.setLevel(log_level.upper())
        handler = RotatingFileHandler('network_scan.log', maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(handler.formatter)
        logger.addHandler(console_handler)

    return logger

logger = setup_logging("INFO")

def discover_active_hosts(target):
    try:
        nm = nmap.PortScanner()
        logger.info("Performing a ping scan to discover active hosts...")
        nm.scan(hosts=target, arguments='-sn')
        active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        logger.info(f"Active hosts discovered: {active_hosts}")
        return active_hosts
    except Exception as e:
        logger.error(f"Error during active host discovery: {str(e)}")
        return []

def resolve_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror) as e:
        hostname = "Unknown"
        logger.warning(f"Could not resolve hostname for IP {ip_address}: {str(e)}")
    return hostname

def nmap_scan(target, scan_type, socketio=None):
    global open_ports_info, devices
    try:
        nm = nmap.PortScanner()
        start_time = time.time()
        logger.info(f"Starting Nmap scan on target: {target} with scan type: {scan_type}")

        nm.scan(hosts=target, arguments=scan_type)
        hosts = nm.all_hosts()
        total_hosts = len(hosts)

        devices = []
        open_ports_info = []

        with tqdm(total=total_hosts, desc="Nmap scanning", unit="host") as pbar:
            for host in hosts:
                try:
                    pbar.update(1)
                    if socketio:
                        socketio.emit('scan_progress', {'progress': pbar.n / total_hosts * 100})

                    hostname = nm[host].hostname()
                    state = nm[host].state()
                    mac = nm[host]['addresses'].get('mac', 'N/A')
                    vendor = nm[host]['vendor'].get(mac, 'N/A')
                   
                    services = []

                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            service = nm[host][proto][port]['name']
                            port_state = nm[host][proto][port]['state']
                            services.append({
                                'port': port,
                                'service': service,
                                'state': port_state
                            })
                            if port_state == 'open':
                                open_ports_info.append(f"Host: {host}, Protocol: {proto}, Port: {port}, Service: {service}, State: {port_state}")

                    device = {
                        'ip': host,
                        'hostname': hostname,
                        'state': state,
                        'mac': mac,
                        'vendor': vendor,
                        'services': services,
                    }
                    devices.append(device)

                except Exception as e:
                    logger.error(f"Error scanning host {host}: {str(e)}")

        duration = time.time() - start_time
        logger.info(f"Nmap scan completed in {duration:.2f} seconds")
        return devices
    except Exception as e:
        logger.error(f"Error scanning with Nmap: {str(e)}")
        return []

def capture_packets(packet_count, output_file):
    global packet_details  # Ensure this is the global variable
    try:
        packet_details = []  # Clear packet details before capturing
        with tqdm(total=packet_count, desc="Capturing packets") as pbar:
            def update_pbar(packet):
                pbar.update(1)
                analyze_packet(packet)
            
            packets = sniff(count=packet_count, filter="ip", prn=update_pbar)
        wrpcap(output_file, packets)
        logger.info(f"Captured packets saved to {output_file}")
        logger.info(f"Packet details captured: {packet_details}")  # Log captured packet details
    except Exception as e:
        logger.error("Error capturing packets: %s", str(e))


packet_details = []  # Global list to store packet details

def analyze_packet(packet):
    global packet_details  # Declare the global variable

    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            connection_id = tuple(sorted([ip_src, ip_dst]))

            if connection_id not in connections:
                connections[connection_id] = {'start_time': time.time(), 'end_time': None}

            connections[connection_id]['end_time'] = time.time()

            logger.info(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
            packet_details.append({'src_ip': ip_src, 'dst_ip': ip_dst})  # Store the details

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                logger.info(f"Source Port: {src_port}, Destination Port: {dst_port}")
                packet_details[-1].update({'src_port': src_port, 'dst_port': dst_port})  # Update details

                if packet.haslayer(Raw):
                    data = packet[Raw].load
                    logger.debug("Data: %s", data.decode('utf-8', errors='ignore'))

    except Exception as e:
        logger.error("Error analyzing packet: %s", str(e))

def retrieve_arp_table():
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        arp_output = result.stdout
        logger.info("ARP Table:")
        logger.info(arp_output)
        
        return arp_output
    except Exception as e:
        logger.error("Error retrieving ARP table: %s", str(e))
        return "Error retrieving ARP table."

def alert_if_open_ports():
    global open_ports_info, email_alerts
    if open_ports_info:
        subject = "Suspicious Network Activity Detected: Open Ports"
        body = "Suspicious activity detected on the network. The following ports are open:\n\n" + "\n".join(open_ports_info)
        send_email_alert(subject, body, "recipient@example.com")
        logger.warning("Suspicious network activity detected and email alert sent with open port details!")
        email_alerts.append(f"Alert email sent: {subject}")

def send_email_alert(subject, body, to_email):
    from_email = os.getenv('FROM_EMAIL')
    from_password = os.getenv('FROM_EMAIL_PASSWORD')

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email

    try:
        server = smtplib.SMTP_SSL('smtp.example.com', 465)
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        logger.info(f"Alert email sent to {to_email}")
        email_alerts.append(f"Alert email sent to {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        email_alerts.append(f"Error sending email: {str(e)}")

def categorize_devices(devices, criteria):
    categories = {}
    
    for device in devices:
        key = None
        ip = device['ip']
        if criteria == 'type':
            hostname = device['hostname'].lower()
            mac = device['mac']
            
            if 'desktop' in hostname or 'laptop' in hostname or 'pc' in hostname:
                key = 'Computer'
            elif 'iot' in hostname or 'camera' in hostname or 'sensor' in hostname or 'vacuum' in hostname:
                key = 'IoT Device'
            elif 'phone' in hostname or 'mobile' in hostname or 'android' in hostname or 'iphone' in hostname:
                key = 'Mobile Phone'
            elif 'modem' in hostname or 'router' in hostname:
                key = 'Modem/Router'
            else:
                key = 'Other'
        elif criteria == 'purpose':
            key = "Business" if "server" in device['hostname'].lower() else "Personal"
        elif criteria == 'location':
            key = "Office" if "office" in device['hostname'].lower() else "Home"
        elif criteria == 'segment':
            key = "LAN" if ip.startswith("192.168") else "WAN"
        elif criteria == 'manufacturer':
            key = device['vendor']
        elif criteria == 'ip':
            key = "Static" if device['state'] == 'up' else "Dynamic"
        elif criteria == 'connection':
            key = "Wired" if "eth" in device['hostname'].lower() else "Wireless"
        elif criteria == 'security':
            key = "High" if any(service in device['services'] for service in ['ssh', 'ftp', 'telnet']) else "Low"
        
        if key not in categories:
            categories[key] = []
        
        categories[key].append(device)
    
    return categories

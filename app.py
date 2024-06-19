import threading
from gevent import monkey
monkey.patch_all()

import os
import signal
import subprocess
import re
import socket
import time
from flask import Flask, render_template, request, jsonify, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler
import nmap
from email.mime.text import MIMEText
import smtplib
from scapy.all import IP, TCP, Raw, sniff, wrpcap
from tqdm import tqdm

app = Flask(__name__)
socketio = SocketIO(app)
GEVENT_SUPPORT = True

from_email = os.getenv('FROM_EMAIL')
from_password = os.getenv('FROM_EMAIL_PASSWORD')

NMAP_SCAN_OPTIONS = [
    "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sP", "-sO", "-sA", "-O", "-sV", "-p", "-T", "-F", "-d", "-v", "--version-light", "--version-intensity", "--osscan-limit", "--osscan-guess", "--max-retries", "--max-scan-delay", "--defeat-rst-ratelimit", "--defeat-icmp-ratelimit", "--reason", "--packet-trace"
]

devices = []
log_messages = []
arp_table = ""
open_ports_info = []
email_alerts = []
scanner_mac_address = ""
packet_details = []
alerts = []

def validate_ip(ip):
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

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
    global packet_details
    try:
        packet_details = []
        with tqdm(total=packet_count, desc="Capturing packets") as pbar:
            def update_pbar(packet):
                pbar.update(1)
                analyze_packet(packet)
            
            packets = sniff(count=packet_count, filter="ip", prn=update_pbar)
        wrpcap(output_file, packets)
        logger.info(f"Captured packets saved to {output_file}")
        logger.info(f"Packet details captured: {packet_details}")
    except Exception as e:
        logger.error("Error capturing packets: %s", str(e))

connections = {}
def detect_anomalies(devices, logger):
    alerts = []
    for device in devices:
        for service in device['services']:
            if service['state'] == 'open' and service['service'] in ['ssh', 'ftp', 'telnet']:
                alert_message = f"Suspicious open port detected: {service['service']} on {device['ip']}"
                alerts.append(alert_message)
                logger.info(alert_message)  # Log each alert for debugging
    return alerts

def analyze_packet(packet):
    global packet_details

    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            connection_id = tuple(sorted([ip_src, ip_dst]))

            if connection_id not in connections:
                connections[connection_id] = {'start_time': time.time(), 'end_time': None}

            connections[connection_id]['end_time'] = time.time()

            logger.info(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
            packet_details.append({'src_ip': ip_src, 'dst_ip': ip_dst})

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                logger.info(f"Source Port: {src_port}, Destination Port: {dst_port}")
                packet_details[-1].update({'src_port': src_port, 'dst_port': dst_port})

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
        send_email_alert(subject, body, "acarbaran35@gmail.com")
        logger.warning("Suspicious network activity detected and email alert sent with open port details!")
        email_alerts.append(f"Alert email sent: {subject}")

def send_email_alert(subject, body, to_email):
    from_email = os.getenv('networkspider88@gmail.com')
    from_password = os.getenv('NetWork55!125')

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
        hostname = device.get('hostname', '').lower()
        ip = device.get('ip', '')
        mac = device.get('mac', '')
        vendor = device.get('vendor', 'Unknown')
        state = device.get('state', 'unknown')
        services = device.get('services', [])
        
        if criteria == 'type':
            if any(keyword in hostname for keyword in ['desktop', 'laptop', 'pc']):
                key = 'Computer'
            elif any(keyword in hostname for keyword in ['iot', 'camera', 'sensor', 'vacuum']):
                key = 'IoT Device'
            elif any(keyword in hostname for keyword in ['phone', 'mobile', 'android', 'iphone']):
                key = 'Mobile Phone'
            elif any(keyword in hostname for keyword in ['modem', 'router']):
                key = 'Modem/Router'
            else:
                key = 'Other'
        elif criteria == 'purpose':
            key = "Business" if "server" in hostname else "Personal"
        elif criteria == 'location':
            key = "Office" if "office" in hostname else "Home"
        elif criteria == 'segment':
            key = "LAN" if ip.startswith("192.168") else "WAN"
        elif criteria == 'manufacturer':
            key = vendor
        elif criteria == 'ip':
            key = "Static" if state == 'up' else "Dynamic"
        elif criteria == 'connection':
            key = "Wired" if "eth" in hostname else "Wireless"
        elif criteria == 'security':
            key = "High" if any(service in services for service in ['ssh', 'ftp', 'telnet']) else "Low"
        
        if key not in categories:
            categories[key] = []
        
        categories[key].append(device)
    
    return categories

# Scan options
FAST_SCAN_OPTIONS = {
    "Top Ports Scan": "-F",
    "Ping Scan": "-sn",
    "Quick Service Version Detection": "-sS -sV --version-intensity 0 -T4"
}

DEEP_SCAN_OPTIONS = {
    "Intense Scan": "-sS -A -T4",
    "Comprehensive Scan": "-sS -sV -O --script=default -T4",
    "Full Scan with UDP": "-sS -sU -p 1-65535 -T4 -A"
}

def emit_log_and_progress(message, current_step, total_steps):
    progress = (current_step / total_steps) * 100
    log_messages.append(message)
    socketio.emit('scan_progress', {'message': message, 'progress': progress})
    logger.info(message)

def get_own_mac_address():
    try:
        if os.name == 'nt':  # Windows
            output = subprocess.check_output('getmac', universal_newlines=True)
            mac_address = re.search(r'([0-9A-F]{2}[-:]){5}([0-9A-F]{2})', output, re.I).group()
        else:  # Unix/Linux
            output = subprocess.check_output('ifconfig', universal_newlines=True)
            mac_address = re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]{2})', output, re.I).group()
        return mac_address
    except Exception as e:
        logger.error(f"Error retrieving own MAC address: {e}")
        return "Unknown"

def run_scan(target, packet_count, log_level, pcap_output, nmap_options, active_only):
    global devices, log_messages, arp_table, open_ports_info, email_alerts, scanner_mac_address, packet_details, alerts
    logger = setup_logging(log_level)
    
    total_steps = 4  # Number of steps in the process (discover active hosts, nmap scan, packet capture, arp table retrieval)
    current_step = 0

    # Retrieve own MAC address, IPs, and hostname
    scanner_mac_address = get_own_mac_address()  # Store the scanner's MAC address
   
    if active_only:
        emit_log_and_progress("Starting active host discovery...", current_step, total_steps)
        active_hosts = discover_active_hosts(target)
        current_step += 1
        if not active_hosts:
            logger.error("No active hosts found. Exiting.")
            socketio.emit('scan_error', {'message': 'No active hosts found.'})
            return
        emit_log_and_progress("Active hosts discovered: {}".format(active_hosts), current_step, total_steps)
        devices.extend(nmap_scan(' '.join(active_hosts), nmap_options, socketio))
    else:
        emit_log_and_progress("Starting Nmap scan...", current_step, total_steps)
        devices.extend(nmap_scan(target, nmap_options, socketio))
    current_step += 1
    emit_log_and_progress("Nmap scan completed.", current_step, total_steps)

    emit_log_and_progress("Starting packet capture...", current_step, total_steps)
    capture_packets(packet_count, pcap_output)
    current_step += 1
    emit_log_and_progress("Packet capture completed.", current_step, total_steps)

    emit_log_and_progress("Retrieving ARP table...", current_step, total_steps)
    arp_table = retrieve_arp_table()
    current_step += 1
    emit_log_and_progress("ARP table retrieval completed.", current_step, total_steps)

    emit_log_and_progress("Alerting if any open ports are found...", current_step, total_steps)
    alert_if_open_ports()

    alerts = detect_anomalies(devices, logger)
    logger.info(f"Alerts detected: {alerts}")  # Log alerts for debugging

    socketio.emit('scan_complete', {'devices': devices, 'log_messages': log_messages, 'arp_table': arp_table, 'open_ports_info': open_ports_info, 'email_alerts': email_alerts, 'scan_type': scan_type, 'packet_details': packet_details, 'alerts': alerts})

@app.route('/')
def index():
    return render_template('index.html', nmap_options=NMAP_SCAN_OPTIONS)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    global devices, log_messages, arp_table, open_ports_info, email_alerts, scanner_mac_address, packet_details, scan_type, alerts
    devices = []  # Clear the devices list before starting a new scan
    packet_details = []  # Clear packet details before starting a new scan
    target = request.form['target']
    packet_count = int(request.form['packet_count'])
    log_level = request.form['log_level']
    pcap_output = request.form['pcap_output']
    scan_type = request.form['scan_type']
    active_only = request.form.get('active_only')

    # Map the selected scan type to the corresponding Nmap options
    if scan_type in FAST_SCAN_OPTIONS:
        nmap_options = FAST_SCAN_OPTIONS[scan_type]
    elif scan_type in DEEP_SCAN_OPTIONS:
        nmap_options = DEEP_SCAN_OPTIONS[scan_type]
    else:
        return jsonify({'status': 'Invalid scan type selected'})

    logger = setup_logging(log_level)
    log_messages = []
    open_ports_info = []
    email_alerts = []

    thread = threading.Thread(target=run_scan, args=(target, packet_count, log_level, pcap_output, nmap_options, active_only))
    thread.start()

    return jsonify({'status': 'Scan started', 'scan_type': scan_type})

@app.route('/results')
def results():
    global devices, log_messages, arp_table, open_ports_info, email_alerts, scanner_mac_address, packet_details, alerts
    
    criteria_list = ['type', 'purpose', 'location', 'segment', 'manufacturer', 'ip', 'connection', 'security']
    categorized_devices = {criteria: categorize_devices(devices, criteria) for criteria in criteria_list}
    selected_scan_type = request.args.get('scan_type')

    # Ensure alerts is defined
    if 'alerts' not in globals():
        alerts = []

    logger.info(f"Rendering results with alerts: {alerts}")

    return render_template('results.html', 
                           categorized_devices=categorized_devices, 
                           log_messages=log_messages, 
                           arp_table=arp_table, 
                           open_ports_info=open_ports_info, 
                           email_alerts=email_alerts, 
                           scan_type=selected_scan_type, 
                           scanner_mac_address=scanner_mac_address, 
                           packet_details=packet_details, 
                           alerts=alerts)

@app.route('/exit')
def exit_app():
    # Terminate the application
    os.kill(os.getpid(), signal.SIGINT)
    return "Server shutting down..."

def background_thread():
    global devices  # Declare devices as global to avoid NameError
    while True:
        socketio.emit('network_data', {'devices': devices})
        socketio.sleep(5)

@socketio.on('connect')
def handle_connect():
    emit('response', {'message': 'Connected to server!'})

if __name__ == '__main__':
    devices = []  # Initialize the devices variable
    thread = threading.Thread(target=background_thread)
    thread.start()
    socketio.run(app, port=5000)

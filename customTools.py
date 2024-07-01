import subprocess
import psutil
import socket
import os
import configparser
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.http import HTTP
from datetime import datetime
import json
import uuid
from pyx import canvas, text
import sqlite3

def Get_Device():
    try:
        # Run command 
        result = subprocess.run(["systeminfo"], capture_output=True, text=True, check=True)

        # Format Output
        lines = result.stdout.strip().splitlines()
        hotfix_index = next((i for i, line in enumerate(lines) if "Hotfix(s):" in line), len(lines))
        lines = lines[:hotfix_index]

        # Join lines with "\n" after each line
        formatted_output = "\n".join(line.lstrip('\n') for line in lines)
        MESSAGE = formatted_output

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        MESSAGE = "Error: Device Info Not Available"
    return MESSAGE

def Get_IP():
    try:
        # Run command 
        result = subprocess.run(["ipconfig","/all"], capture_output=True, text=True, check=True)

        # Format Output
        lines = result.stdout.strip().splitlines()

        # Join lines with "\n" after each line
        formatted_output = "\n".join(line.lstrip('\n') for line in lines)
        MESSAGE = formatted_output

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        MESSAGE = "Error: IP Info Not Available"
    return MESSAGE

def Get_NetStat():
    try:
        # Run Command
        result = subprocess.run(["netstat"], capture_output=True, text=True, check=True)
         
        # Format Output
        lines = result.stdout.strip().splitlines()

        # Join lines with "\n" after each line
        formatted_output = "\n".join(line.lstrip('\n') for line in lines)
        MESSAGE = formatted_output
    
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        MESSAGE = "Error: Network Info Not Available"
    return MESSAGE   

def Get_Interface_Names():
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    interface_dict = {}

    for name, addrs in interfaces.items():
        ipv4_addrs = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        #Filter out all Link-Local Addresses by excluding fe80
        ipv6_addrs = [addr.address for addr in addrs if addr.family == socket.AF_INET6 and not addr.address.startswith('fe80::')]
        if_stats = stats.get(name)

        connection_type = "unknown"
        if if_stats and if_stats.isup:
            if "wireless" in name.lower() or "wlan" in name.lower():
                connection_type = "wireless"
            else:
                connection_type = "ethernet"

        interface_dict[name] = {
            'index': list(interfaces.keys()).index(name),
            'connection_type': connection_type,
            'ipv4_addresses': ipv4_addrs,
            'ipv6_addresses': ipv6_addrs
        }
        
    return interface_dict

# Scanner Tools
def Get_Network_Data():
    def extract_sub_domain(ipv4,subnet):
        # Determine the number of octets to join based on the subnet mask
        subnet_octets = subnet.split('.');
        zero_octets = [octet for octet in subnet.split('.') if octet == '0']
        num_octets = len(subnet_octets) - len(zero_octets);
        
        octets = ipv4.split('.')
        sub_domain = '.'.join(octets[:num_octets])
        return sub_domain
    
    network_dict = {}

    # Get hostname
    hostname = socket.gethostname()

    # Get all network interfaces
    net_ifs = psutil.net_if_addrs()

    # Iterate over each interface
    for interface_name, interface_addresses in net_ifs.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                interface_info = {}
                interface_info['ipv4_address'] = address.address
                interface_info['netmask'] = address.netmask
                interface_info['broadcast_ip'] = address.broadcast
                interface_info['sub_domain'] = extract_sub_domain(address.address,address.netmask)
                network_dict.setdefault(interface_name, {}).update(interface_info)

    # Get gateway, assuming a single default gateway for all interfaces
    default_gateway = psutil.net_if_stats().get('defaultgateway')
    if default_gateway:
        for interface_name in network_dict:
            network_dict[interface_name]['gateway'] = default_gateway

    # Add hostname to each interface
    for interface_name in network_dict:
        network_dict[interface_name]['hostname'] = hostname
        
    return network_dict

def Get_Start_End_IP_Ping(subnet,subdomain):
    # Calculate network address for netmask
    octets = subnet.split('.');
        
    # Split Subdomain
    start = subdomain.split('.');
    while len(start) < len(octets):
        start.append('0')
    end = subdomain.split('.');
    while len(end) < len(octets):
        end.append('255')
        
    start_ip = '.'.join(start)
    end_ip = '.'.join(end)
    
    return start_ip,end_ip

def expand(packet):
    yield packet
    while packet.payload:
        packet = packet.payload
        yield packet

def packet_to_dict(packet):
    # Get Timestamp
    timestamp = float(packet.time);
    datetime_obj = datetime.fromtimestamp(timestamp);
    # Convert datetime object to a string in a specific format
    formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
    
    protocols = [layer.__name__ for layer in packet.layers()]
    packet_data = {
        "Timestamp": formatted_datetime,
        "Bytes on Wire": len(packet),
        "Bytes Captured": len(packet.original),
        "Interface": packet.sniffed_on,
        "Source": packet[0][1].src if packet.haslayer('IP') else packet.src,
        "Source Port": packet.sport if hasattr(packet, 'sport') else None,
        "Destination": packet[0][1].dst if packet.haslayer('IP') else packet.dst,
        "Destination Port": packet.dport if hasattr(packet, 'dport') else None,
        "Protocols": protocols,
        "Payload":  bytes(packet.payload),
        "Packet" : packet
    }
   
    return packet_data;

def packet_scanner(packet):
    error = "0"
    if Raw in packet:
        print("Raw Detected");
        raw_data = packet[Raw].load.decode('utf-8', 'ignore')
        if "SELECT" in raw_data or "INSERT" in raw_data or "DROP" in raw_data: # Check SQL Injection
            print("Potential SQL Injection Detected")
            error = "Potential SQL Injection";
    if HTTP in packet:
        print("Unsecure HTTP packet detected") # HTTP Packet
        error = "HTTP Packet";

    return error

def download_packet(destination,timestamp,packet):
    print("Saving")
    sanitized_timestamp = timestamp.replace(":", "-")
    unique_id = uuid.uuid4();
    pcap_file = f"{destination}/{sanitized_timestamp}_{unique_id}.pcap"
    filename = f"{sanitized_timestamp}_{unique_id}.pcap"     

    # Save packets to the specified PCAP file
    wrpcap(pcap_file, packet, append=True)
    print(f"Packet saved to {pcap_file}")
    
    return filename, pcap_file

def load_packets(destination):
    packet_dicts = []
    
    # Iterate over files in the directory
    for filename in os.listdir(destination):
        if filename.endswith(".pcap"):
            file_path = os.path.join(destination, filename)

            # Use rdpcap from scapy to read pcap file
            packets = rdpcap(file_path)
            
            for packet in packets:
                # Convert each packet to dictionary and append to list
                packet_dict = packet_to_dict(packet);
                packet_dict["Directory"] = file_path;
                packet_dict["File"] = filename;
                packet_dicts.append(packet_dict);

    return packet_dicts

def download_packet_diagram(destination,packets,name):
    name_prefix = f"{name}_packet_diagram";
    
    for index, packet in enumerate(packets[0:1]):
        file_path = f"{destination}/{name_prefix}_packet_{index}.pdf"
        
        packet.pdfdump(layer_shift=1)
            

def delete_packet_download(destination):
    if os.path.isfile(destination):
        try:
            os.remove(destination)
            print(f"Deleted {destination}")
        except Exception as e:
            print(f"Error deleting {destination}: {e}")
    else:
        print(f"The file {destination} does not exist.")
        
# System Tools
def updateconfig(settings_dict):
    json_default_dir = "settings.json";
    # Check if JSON file exists
    if os.path.exists(json_default_dir):
        # Load existing JSON data
        with open(json_default_dir, 'r') as file:
            existing_data = json.load(file)
    else:
        # If JSON file doesn't exist, create an empty dictionary
        existing_data = {
            "Analyze": "pcap_download",
            "Save": "pcap_download",
            "Quarantine": "pcap_download/quarantine",
            "PDF" : "reports_pdf",
            "Diagram" : "packet_diagrams"
        }   

    # Compare with existing data and update if there are changes
    if existing_data != settings_dict:
        existing_data.update(settings_dict)

        # Write updated JSON data back to the file
        with open(json_default_dir, 'w') as file:
            json.dump(existing_data, file, indent=4)

        print(f"JSON file Updated");
    else:
        print("No changes detected. JSON file not updated.")
    

def loadconfig():
    json_default_dir = "settings.json";
    if os.path.exists(json_default_dir):
        # Load JSON data from file into a dictionary
        with open(json_default_dir, 'r') as file:
            data = json.load(file)
        return data
    else:
        print(f"JSON file '{json_default_dir}' not found. Loading Default Config.")
        default_config = {
            "Analyze": "pcap_download",
            "Save": "pcap_download",
            "Quarantine": "pcap_download/quarantine",
            "PDF" : "reports_pdf",
            "Diagram" : "packet_diagrams"
        }
        
        save_path = "pcap_download";
        os.makedirs(save_path, exist_ok=True);
        os.makedirs(os.path.join(save_path, "quarantine"), exist_ok=True);
        os.makedirs("reports_pdf",exist_ok=True);
        os.makedirs("packet_diagrams",exist_ok=True);
        
        return default_config 

def shutdown(root,running_threads):
    print("Shutting Down Application...")
    root.destroy();
    os._exit(0);
    

# Database Tools
def create_tables():
    conn = sqlite3.connect('network_monitor.db');
    sql = conn.cursor();   
    
    sql.execute('''
        CREATE TABLE IF NOT EXISTS trafficalert (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT NOT NULL,
        IP_Src TEXT,        
        IP_Dest TEXT,
        Average FLOAT,
        Threshold INTEGER,
        Packet_Count INTEGER        
    )
    ''')
    
    sql.execute('''
        CREATE TABLE IF NOT EXISTS packetalert (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT NOT NULL,
        File TEXT,
        Type TEXT,
        QuarantineDir TEXT        
    )
    ''')

    sql.execute('''
        CREATE TABLE IF NOT EXISTS trafficbase (
        IP_Src TEXT,
        IP_Dest TEXT,
        Average FLOAT,
        Count INTEGER,
        Alerts INTEGER        
    )
    ''')

    sql.execute('''
        CREATE TABLE IF NOT EXISTS ipscan (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT NOT NULL,
        IP_Src TEXT,
        IP_Dest TEXT
    )
    ''')

    sql.execute('''
        CREATE TABLE IF NOT EXISTS pingsweep (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT NOT NULL,
        Start_IP TEXT,
        End_IP TEXT
    )
    ''')

    sql.execute('''
        CREATE TABLE IF NOT EXISTS nmap (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        Timestamp TEXT NOT NULL,
        Scan TEXT,
        IP TEXT,
        Start_Port TEXT,
        End_Port TEXT
    )
    ''')

    conn.commit()
    conn.close()
    

def insert_table(table, input_dict):
    conn = sqlite3.connect('network_monitor.db')
    sql = conn.cursor()
    
    columns = ', '.join(input_dict.keys())
    placeholders = ', '.join('?' for _ in input_dict)
    values = list(input_dict.values())

    sql.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', values)
    
    # Commit & Close    
    conn.commit()
    conn.close()
    
def update_row(table,input_dict,condition):
    conn = sqlite3.connect('network_monitor.db')
    sql = conn.cursor()    

    # Commit & Close    
    conn.commit()
    conn.close()
    
def load_traffic_baseline(src, dest):
    info_dict = {}
    conn = sqlite3.connect('network_monitor.db')
    sql = conn.cursor()    

    query = '''
        SELECT * FROM trafficbase
        WHERE IP_Src = ? AND IP_Dest = ?
    '''
    sql.execute(query, (src, dest))
    row = sql.fetchone()
    
    if row is not None:
        print("Updating Existing Traffic Log")
        # Access column in the row
        average = row[2]  # Average
        count = row[3]  # Count
        alerts = row[4]
    else:
        print("Unique Src and Dest Detected")
        average = 0;
        count = 0;
        alerts = 0;
    
    info_dict = {
         "Average": average,
         "Count": count,
         "Alerts": alerts
        }

    # Commit & Close    
    conn.commit()
    conn.close()    
    
    return info_dict;

def update_traffic_baseline(input_dict):
    conn = sqlite3.connect('network_monitor.db')
    sql = conn.cursor()
    sql.execute('''
                DELETE FROM trafficbase
                WHERE IP_Src = ? AND IP_Dest = ?
            ''', (input_dict["IP_Src"], input_dict["IP_Dest"]))
    sql.execute('''
        INSERT OR REPLACE INTO trafficbase (IP_Src, IP_Dest, Average, Count, Alerts)
        VALUES (?, ?, ?, ?, ?)
    ''', (input_dict["IP_Src"], input_dict["IP_Dest"], input_dict["Average"], input_dict["Count"], input_dict["Alerts"]))
    conn.commit()
    conn.close()
    
def fetch_data_query(query):
    conn = sqlite3.connect('network_monitor.db')
    sql = conn.cursor()  
    sql.execute(query)
    rows = sql.fetchall()
    conn.close()
    return rows
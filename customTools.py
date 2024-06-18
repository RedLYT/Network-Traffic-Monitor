import subprocess
import psutil
import socket
import os

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


# System Tools
def shutdown(root,running_threads):
    print("Shutting Down Application...")
    root.destroy();
    os._exit(0);
    


import subprocess
import threading
import psutil
import socket

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
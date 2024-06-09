import subprocess
import socket
import psutil
import re
import xml.etree.ElementTree as ET


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


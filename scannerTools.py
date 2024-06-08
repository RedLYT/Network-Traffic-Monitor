import subprocess
import socket
import psutil
import re
import xml.etree.ElementTree as ET


def Get_Network_Data():
    def extract_sub_domain(ipv4):
        # Split the IPv4 address and join the first three octets
        octets = ipv4.split('.')
        sub_domain = '.'.join(octets[:3])
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
                interface_info['sub_domain'] = extract_sub_domain(address.address)
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



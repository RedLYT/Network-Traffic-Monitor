from scapy.all import *

def send_test_packets():
    destination = '192.168.0.34' # '192.168.0.34' '127.0.0.1'  # Use localhost for the same device
    # Create a raw packet with potential SQL injection payload
    sql_injection_packet = IP(src=destination, dst=destination) / TCP(dport=80) / Raw(load="SELECT * FROM users;")
    send(sql_injection_packet)

    # Create an HTTP packet to test HTTP detection
    http_packet = IP(src=destination, dst=destination) / TCP(dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    send(http_packet)
    print("Test Packets Sent: " + str(destination))
    
send_test_packets()


def getCurrentNetwork(target):
    Client_Hostname = socket.getHostname();
    IP_Settings = subprocess.run('ipconfig /all',stdout=subprocess.PIPE,text=True).stdout.lower();
    scan=False;
    IP_Address = "";
    Default_Gateway = "";
    Subnet_Mask = "";
    DNS_Servers = "";
    scan = "";
    
    
    for i in IP_Settings.split('\n'):
        #Toggle select between WLAN and Wired Ethernet Connection
        
        #if 'wireless' in i: 
        #   scan=True;
        if((i != None) and ("ethernet adapter ethernet:" in i)):
            scan = True
        #if((i != None) and ("ethernet adapter vmware network adapter vmnet8:" in i)): scan=True;
        #Only get value 1st iternation. If value != null don't retrieve
        if scan:
            if 'ipv4 address' in i and IP_Address == "": 
                IP_Address = i.split(':')[1].strip();
                IP_Address = IP_Address.replace("(preferred)","");
            if 'default gateway' in i and Default_Gateway == "": 
                Default_Gateway = i.split(':')[1].strip();   
            if 'subnet mask' in i and Subnet_Mask == "": 
                Subnet_Mask = i.split(':')[1].strip(); 
            if 'dns servers' in i and DNS_Servers == "": 
                DNS_Servers = i.split(':')[1].strip();         

        MESSAGE = "IP v4 ad: " +  IP_Address;
        MESSAGE += "      Subnet: " + Subnet_Mask;
        MESSAGE += "\nHostname: " + Client_Hostname;
        MESSAGE += "           DNS: " + DNS_Servers;
        MESSAGE += "\nGateway:  " + Default_Gateway;

        data = {
            'ip' : IP_Address,
            'client_host' : Client_Hostname,
            'dns_servers' : DNS_Servers,
            'default_gateway' : Default_Gateway,
            'message' : MESSAGE
            }        

    return data;

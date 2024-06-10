from csv import Sniffer
import sys
from io import StringIO
import tkinter as tk;
from tkinter import messagebox as mb;
from tkinter import SEL, ttk
import psutil;
import time;
import datetime;
import platform;
import os;
import socket;
import threading;
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.ticker as ticker
import scapy.all as scapy
import nmap

from turtle import width, window_height;

#Custom Modules
import scannerTools as scanT;
import deviceTools as devT;

#Globals
window = tk.Tk();
window.title ("Python - Network Traffic Monitoring System - 1201201251 FYP - 2024 ");

#Configure Dimension
window_Width = 1344;
window_Height = 756;
ScreenWidth = window.winfo_screenwidth();
ScreenHeight = window.winfo_screenheight();
Appear_in_the_Middle = '%dx%d+%d+%d' % (window_Width, window_Height, (ScreenWidth - window_Width) / 2, (ScreenHeight - window_Height) / 2);
window.geometry(Appear_in_the_Middle);
window.resizable(width=False, height=False);
GUI = None;

#Main GUI
class GUI:
    interface_dict = {};
    network_dict = {};
    current_network_dict = {};
    src_ip_dict = {};
    adapter = "";
    adapter_isLive = False;
    ipscan_isLive = False;
    pingsweep_isLive = False;
    NMAPScan_isLive = False;
    running_threads = [];
    stop_threads = False;

    def __init__(self, master=None): 
        #Stop Thread Event
        self.stop_event = threading.Event()        
        
        #Tabs
        tabTools = ttk.Notebook(window);
        device = ttk.Frame(tabTools);
        scanners = ttk.Frame(tabTools);
        sniffer = ttk.Frame(tabTools);
        analyzer = ttk.Frame(tabTools);
        options = ttk.Frame(tabTools);

        tabTools.add(device, text="Device");
        tabTools.add(scanners, text="Network Scanners");
        tabTools.add(sniffer, text="Packet Sniffer");
        tabTools.add(analyzer, text="Packet Analyzer");
        tabTools.add(options, text="Options");
        tabTools.pack(expand=1, fill="both")

        # Device Frame A : Device Info | Device Tab
        devA_Height = 410;
        devA_Width = 705;
        self.Current_Device = tk.LabelFrame(device);
        self.Current_Device.configure(height=devA_Height, width=devA_Width, borderwidth=3, relief="groove", text="Device Info");
        self.Current_Device.place(anchor="nw", x=5, y=5);  

        self.Current_Device_Info = tk.Text(self.Current_Device,height=25, width=98);
        self.Current_Device_Info.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Current_Device_Info.place(anchor="nw", x=2, y=2);                                       
        self.Current_Device_Info.insert("1.0",devT.Get_Device());
        self.Current_Device_Info.configure(state='disabled');

        # Device Frame B : IP Info | Device Tab
        devB_Height = 308;
        devB_Width = 705;
        self.Current_IP = tk.LabelFrame(device);
        self.Current_IP.configure(height=devB_Height, width=devB_Width, borderwidth=3, relief="groove", text="IP Info");
        self.Current_IP.place(anchor="nw", x=5, y=420);  

        self.Current_IP_Info = tk.Text(self.Current_IP, height=18, width=98);
        self.Current_IP_Info.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Current_IP_Info.place(anchor="nw", x=2, y=2);                                       
        self.Current_IP_Info.insert("1.0",devT.Get_IP())      
        self.Current_IP_Info.configure(state='disabled');

        # Device Frame C : Network Stats | Device Tab
        devC_Height = 722;
        devC_Width = 310;
        self.Current_Network = tk.LabelFrame(device);
        self.Current_Network.configure(height=devC_Height, width=devC_Width, borderwidth=3, relief="groove", text="Network Info");
        self.Current_Network.place(anchor="nw", x=715, y=5);  

        self.Current_Network_Info = tk.Text(self.Current_Network, height=46, width=42);
        self.Current_Network_Info.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Current_Network_Info.place(anchor="nw", x=2, y=2); 
        self.Current_Network_Info.insert("1.0", "Loading Active Connections...\nPlease Wait...(Est Time : 60seconds)")
        self.Current_Network_Info.configure(state='disabled');
        self.update_netstat_info();

        # Device Frame D : Bandwidth Monitor | Device Tab
        devD_Height = 722;
        devD_Width = 310;
        self.Current_Bandwidth = tk.LabelFrame(device);
        self.Current_Bandwidth.configure(height=devD_Height, width=devD_Width, borderwidth=3, relief="groove", text="Bandwidth Info");
        self.Current_Bandwidth.place(anchor="nw", x=1030, y=5);     

        self.System_Bandwidth_Label = tk.Label(self.Current_Bandwidth);
        self.System_Bandwidth_Label.configure(text="System Bandwidth", font=('Helvetica',10,'bold'));
        self.System_Bandwidth_Label.place(anchor="nw", x=2,y=2);

        # Current Usage Throughput Chart        
        self.fig, self.ax = plt.subplots()
        self.fig.patch.set_facecolor('#f0f0f0') 
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.Current_Bandwidth)
        self.canvas.get_tk_widget().place(anchor="nw", height= 295, width=295, x=4, y=20)

        # Current Usage
        self.Current_Bandwidth_Speed = tk.Text(self.Current_Bandwidth, height=3, width=41);
        self.Current_Bandwidth_Speed.configure(background="#f0f0f0", foreground="#000000", borderwidth=0, font="{Courier} 9 {}");
        self.Current_Bandwidth_Speed.place(anchor="nw", x=3, y=320); 
        self.Current_Bandwidth_Speed.configure(state='disabled');
        self.bandwidth_usage_monitor_main();
    
        # Adapter Label
        self.Adapter_Bandwidth_Label = tk.Label(self.Current_Bandwidth);
        self.Adapter_Bandwidth_Label.configure(text="Adapter Bandwidth", font=('Helvetica',10,'bold'));
        self.Adapter_Bandwidth_Label.place(anchor="nw", x=2,y=353);
        
        # Get Adapter Button
        self.Get_Adapter_Button = ttk.Button(self.Current_Bandwidth, text="GET ADAPTERS", width=45,  command=self.get_adapters);
        self.Get_Adapter_Button.place(anchor="nw", x=15, y=375)
        
        # Select Adapter
        self.Select_Adapter = ttk.Combobox(self.Current_Bandwidth,height=10,width=25, state="readonly")
        self.Select_Adapter.place(anchor="nw", x=16, y=406)
        self.get_adapters();

        self.Select_Adapter_Button = ttk.Button(self.Current_Bandwidth, text="SELECT", width=15,  command=lambda: self.bandwidth_usage_monitor_adapter(self.Select_Adapter.get()));
        self.Select_Adapter_Button.place(anchor="nw", x=195, y=404)

        # Display Adapter Details
        self.Current_Adapter_Details = tk.Text(self.Current_Bandwidth, height=13, width=41);
        self.Current_Adapter_Details.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Current_Adapter_Details.place(anchor="nw", x=3, y=438); 
        self.Current_Adapter_Details.configure(state='disabled');

        # Adapter Bandwidth
        self.Current_Adapter_Speed = tk.Text(self.Current_Bandwidth, height=3, width=41);
        self.Current_Adapter_Speed.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="groove", font="{Courier} 9 {}");
        self.Current_Adapter_Speed.place(anchor="nw", x=3, y=644); 
        self.Current_Adapter_Speed.configure(state='disabled');
    
        # Scanner Frame A : Network Details
        scanA_Height = 210;
        scanA_Width = 310;
        self.Current_Network = tk.LabelFrame(scanners);
        self.Current_Network.configure(height=scanA_Height, width=scanA_Width, borderwidth=3, relief="groove", text="Network Info");
        self.Current_Network.place(anchor="nw", x=5, y=5);  

        self.Network_Label = tk.Label(self.Current_Network);
        self.Network_Label.configure(text="Get Host Network Data", font=('Helvetica',10,'bold'));
        self.Network_Label.place(anchor="nw", x=2,y=2);
        
        # Get Adapter Button
        self.Get_Networks_Button = ttk.Button(self.Current_Network, text="GET NETWORKS", width=45,  command=self.get_networks);
        self.Get_Networks_Button.place(anchor="nw", x=15, y=30)
        
        # Select Adapter
        self.Select_Network = ttk.Combobox(self.Current_Network,height=10,width=25, state="readonly")
        self.Select_Network.place(anchor="nw", x=16, y=57)
        self.get_networks();

        self.Select_Network_Button = ttk.Button(self.Current_Network, text="SELECT", width=15,  command=lambda: self.select_network(self.Select_Network.get()));
        self.Select_Network_Button.place(anchor="nw", x=195, y=55)

        # Display Adapter Details
        self.Current_Network_Details = tk.Text(self.Current_Network, height=6, width=41);
        self.Current_Network_Details.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Current_Network_Details.place(anchor="nw", x=3, y=85); 
        self.Current_Network_Details.configure(state='disabled');

        # Scanner Frame B : Ping Sweeper
        scanB_Height = 513;
        scanB_Width = 310;
        self.Ping_Sweeper = tk.LabelFrame(scanners);
        self.Ping_Sweeper.configure(height=scanB_Height, width=scanB_Width, borderwidth=3, relief="groove", text="Ping Sweeper");
        self.Ping_Sweeper.place(anchor="nw", x=5, y=215);
        
        # Start Label
        self.Ping_Start_Label = tk.Label(self.Ping_Sweeper);
        self.Ping_Start_Label.configure(text="START HOST:", font=('Helvetica',10,'bold'));
        self.Ping_Start_Label.place(anchor="nw", x=2,y=5);
        
        # Start Host Input
        self.Ping_Start_Input = tk.Text(self.Ping_Sweeper, height=1, width=25);
        self.Ping_Start_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.Ping_Start_Input.place(anchor="nw", x=100, y=5); 
        self.Ping_Start_Input.insert("1.0", "Input Start Host...")
        self.Ping_Start_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.Ping_Start_Input))
        
        # End Label
        self.Ping_End_Label = tk.Label(self.Ping_Sweeper);
        self.Ping_End_Label.configure(text="END HOST:", font=('Helvetica',10,'bold'));
        self.Ping_End_Label.place(anchor="nw", x=2,y=35);
        
        # End Host Input
        self.Ping_End_Input = tk.Text(self.Ping_Sweeper, height=1, width=25);
        self.Ping_End_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.Ping_End_Input.place(anchor="nw", x=100, y=35); 
        self.Ping_End_Input.insert("1.0", "Input End Host...")
        self.Ping_End_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.Ping_End_Input))
        
        # Start Sweep Button
        self.Start_Stop_Ping_Button = ttk.Button(self.Ping_Sweeper, text="START PING SWEEP", width=20,  command=lambda: self.start_ping_sweep(self.Ping_Start_Input.get("1.0", "end-1c"),self.Ping_End_Input.get("1.0", "end-1c")));
        self.Start_Stop_Ping_Button.place(anchor="nw", x=154, y=65)
        
        # Hosts Label
        self.Ping_Hosts_Label = tk.Label(self.Ping_Sweeper);
        self.Ping_Hosts_Label.configure(text="Hosts Found", font=('Helvetica',10,'bold'));
        self.Ping_Hosts_Label.place(anchor="nw", x=2,y=70);
        
        # Hosts Output
        self.Ping_Hosts_Found = tk.Text(self.Ping_Sweeper, height=15, width=41);
        self.Ping_Hosts_Found.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Ping_Hosts_Found.place(anchor="nw", x=2, y=95); 
        self.Ping_Hosts_Found.configure(state="disable");
        
        # Console Label
        self.Ping_Console_Output_Label = tk.Label(self.Ping_Sweeper);
        self.Ping_Console_Output_Label.configure(text="Console", font=('Helvetica',10,'bold'));
        self.Ping_Console_Output_Label.place(anchor="nw", x=2,y=335);
        
        # Console
        self.Ping_Console_Output = tk.Text(self.Ping_Sweeper,height=8, width=41);
        self.Ping_Console_Output.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Ping_Console_Output.place(anchor="nw", x=5, y=361);                                       
        self.Ping_Console_Output.configure(state='disabled');

        # Scanner Frame C : IP Scanner
        scanC_Height = 722;
        scanC_Width = 505;
        self.IP_Scanner = tk.LabelFrame(scanners);
        self.IP_Scanner.configure(height=scanC_Height, width=scanC_Width, borderwidth=3, relief="groove", text="IP Scanner");
        self.IP_Scanner.place(anchor="nw", x=320, y=5);
        
        # IP Input
        self.IP_Scanner_Input = tk.Text(self.IP_Scanner, height=1, width=42);
        self.IP_Scanner_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.IP_Scanner_Input.place(anchor="nw", x=5, y=5); 
        self.IP_Scanner_Input.insert("1.0", "Input IP Address...")
        self.IP_Scanner_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.IP_Scanner_Input))
        
        # Start/Stop Scan Button
        self.Start_Stop_IP_Button = ttk.Button(self.IP_Scanner, text="START SCAN", width=28, command=lambda: self.start_ip_scan(self.IP_Scanner_Input.get("1.0", "end-1c")));
        self.Start_Stop_IP_Button.place(anchor="nw", x=315, y=5)
        
        # Output
        self.treev = ttk.Treeview(self.IP_Scanner, height=50);
        self.treev.column('#0');
        self.treev.place(x=5, y=40, width=488, height=500)
        
        # Clear Button
        self.Clear_IPScan_Button = ttk.Button(self.IP_Scanner, text="CLEAR", width=35, command=lambda: self.clear_ipscan());
        self.Clear_IPScan_Button.place(anchor="nw", x=265, y=542)
        
        # Console Label
        self.IP_Console_Output_Label = tk.Label(self.IP_Scanner);
        self.IP_Console_Output_Label.configure(text="Console", font=('Helvetica',10,'bold'));
        self.IP_Console_Output_Label.place(anchor="nw", x=2,y=545);
        
        # Console
        self.IP_Console_Output = tk.Text(self.IP_Scanner,height=8, width=69);
        self.IP_Console_Output.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.IP_Console_Output.place(anchor="nw", x=5, y=570);                                       
        self.IP_Console_Output.configure(state='disabled');

        # Scanner Frame D : NMAP Scanner
        scanD_Height = 722;
        scanD_Width = 505;
        self.NMAP_Scanner = tk.LabelFrame(scanners);
        self.NMAP_Scanner.configure(height=scanD_Height, width=scanD_Width, borderwidth=3, relief="groove", text="NMAP Scanner");
        self.NMAP_Scanner.place(anchor="nw", x=830, y=5); 
        
        # Select Scan Type
        self.Select_Scan = ttk.Combobox(self.NMAP_Scanner,height=10,width=25, state="readonly")
        self.Select_Scan['values'] = ("SYN Scan",)
        self.Select_Scan.place(anchor="nw", x=315, y=6) 

        # IP Input
        self.NMAP_Scanner_Input = tk.Text(self.NMAP_Scanner, height=1, width=42);
        self.NMAP_Scanner_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.NMAP_Scanner_Input.place(anchor="nw", x=5, y=5); 
        self.NMAP_Scanner_Input.insert("1.0", "Input IP Address...")
        self.NMAP_Scanner_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.NMAP_Scanner_Input))
        
        # Start/Stop Scan Button
        self.Start_Stop_NMAP_Button = ttk.Button(self.NMAP_Scanner, text="START NMAP SCAN", width=28, command=lambda: self.start_nmap_scan(self.NMAP_Scanner_Input.get("1.0", "end-1c"), self.Select_Scan.get(), self.Port_Start_Input.get("1.0", "end-1c"),self.Port_End_Input.get("1.0", "end-1c")));
        self.Start_Stop_NMAP_Button.place(anchor="nw", x=311, y=64)

        # Check Buttons
        var = tk.IntVar()
        LocalButton = tk.Radiobutton(self.NMAP_Scanner, text="Local", variable=var, value=1, command=lambda: self.scan_button_select(var.get(), self.current_network_dict.get("ipv4", "No Local IP available"), self.current_network_dict.get("subdomain", "No Subdomain Available")))
        LocalButton.place(x=305, y=35)

        RemoteButton = tk.Radiobutton(self.NMAP_Scanner, text="Remote", variable=var, value=2, command=lambda: self.scan_button_select(var.get(), self.current_network_dict.get("ipv4", "No Local IP available"), self.current_network_dict.get("subdomain", "No Subdomain Available")))
        RemoteButton.place(x=355, y=35)

        NetworkButton = tk.Radiobutton(self.NMAP_Scanner, text="Network", variable=var, value=3, command=lambda: self.scan_button_select(var.get(), self.current_network_dict.get("ipv4", "No Local IP available"), self.current_network_dict.get("subdomain", "No Subdomain Available")))
        NetworkButton.place(x=420, y=35)
        var.set(3);
        
        # Start Label
        self.Port_Start_Label = tk.Label(self.NMAP_Scanner);
        self.Port_Start_Label.configure(text="START PORT:", font=('Helvetica',10,'bold'));
        self.Port_Start_Label.place(anchor="nw", x=2,y=35);
        
        # Start Host Input
        self.Port_Start_Input = tk.Text(self.NMAP_Scanner, height=1, width=25);
        self.Port_Start_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.Port_Start_Input.place(anchor="nw", x=100, y=35); 
        self.Port_Start_Input.insert("1.0", "1")
        self.Port_Start_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.Port_Start_Input))
        
        # End Label
        self.Port_End_Label = tk.Label(self.NMAP_Scanner);
        self.Port_End_Label.configure(text="END PORT:", font=('Helvetica',10,'bold'));
        self.Port_End_Label.place(anchor="nw", x=2,y=65);
        
        # End Host Input
        self.Port_End_Input = tk.Text(self.NMAP_Scanner, height=1, width=25);
        self.Port_End_Input.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="ridge", font="{Courier} 9 {}");
        self.Port_End_Input.place(anchor="nw", x=100, y=65); 
        self.Port_End_Input.insert("1.0", "65535")
        self.Port_End_Input.bind("<Button-1>", lambda event: self.trigger_clear_placeholder(event, self.Port_End_Input))

        # Ports Output
        self.NMAP_Output = tk.Text(self.NMAP_Scanner, height=29, width=69);
        self.NMAP_Output.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.NMAP_Output.place(anchor="nw", x=2, y=98); 
        self.NMAP_Output.configure(state="disable");

        # Console Label
        self.NMAP_Console_Output_Label = tk.Label(self.NMAP_Scanner);
        self.NMAP_Console_Output_Label.configure(text="Console", font=('Helvetica',10,'bold'));
        self.NMAP_Console_Output_Label.place(anchor="nw", x=2,y=545);
        
        # Console
        self.NMAP_Console_Output = tk.Text(self.NMAP_Scanner,height=8, width=69);
        self.NMAP_Console_Output.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.NMAP_Console_Output.place(anchor="nw", x=5, y=570);                                       
        self.NMAP_Console_Output.configure(state='disabled');
        
        # Options Frame A : Console
        opA_Height = 410;
        opA_Width = 705;
        self.Console = tk.LabelFrame(options);
        self.Console.configure(height=opA_Height, width=opA_Width, borderwidth=3, relief="groove", text="Console");
        self.Console.place(anchor="nw", x=5, y=5);  

        self.Console_Output = tk.Text(self.Console,height=25, width=98);
        self.Console_Output.configure(background="#DCDCDC", foreground="#000000", borderwidth=3, relief="sunken", font="{Courier} 9 {}");
        self.Console_Output.place(anchor="nw", x=2, y=2);                                       
    
        # Options Frame B : Menu
        opB_Height = 722;
        opB_Width = 295;
        self.Menu = tk.LabelFrame(options);
        self.Menu.configure(height=opB_Height, width=opB_Width, borderwidth=3, relief="groove", text="Menu");
        self.Menu.place(anchor="nw", x=1030, y=5);     
    
        # Shut Down Button
        self.Shut_Down_Button = ttk.Button(self.Menu, text="SHUT DOWN", width=45,  command=lambda: [devT.shutdown(window,self.running_threads), setattr(self, 'stop_threads', True)]);
        self.Shut_Down_Button.place(anchor="nw", x=15, y=375)
    
    # Placeholder Clear
    def trigger_clear_placeholder(self,event,widget):
        widget.delete("1.0", "end");
   
    #Update Netstat w/ Threading
    def update_netstat_info(self):
        def run_netstat():
            netstat_output = devT.Get_NetStat();
            self.Current_Network_Info.configure(state='normal');
            self.Current_Network_Info.delete("1.0", tk.END);
            self.Current_Network_Info.insert("1.0", netstat_output);
            self.Current_Network_Info.configure(state='disabled');
            self.stop_event.set();

        self.stop_event.clear()
        threadStat = threading.Thread(target=run_netstat);
        self.running_threads.append(threadStat);
        threadStat.daemon = True;
        threadStat.start();

    #System Bandwidth Monitor
    def bandwidth_usage_monitor_main(self):
        self.net_in_values = []
        self.net_out_values = []
        
        #Plot Chart
        def update_plot():
            self.ax.clear();
            self.ax.plot(range(len(self.net_in_values)), self.net_in_values, label='IN');
            self.ax.plot(range(len(self.net_out_values)), self.net_out_values, label='OUT');
            self.ax.legend(loc='upper right')
    
            # Set axis labels
            self.ax.set_xlabel('Time (s)', fontsize=8);
            self.ax.set_ylabel('MB/s', fontsize=8, rotation=0);
            # Axis label coords
            self.ax.yaxis.set_label_coords(-0.01, 1.03);
            self.ax.xaxis.set_label_coords(1.0, -0.1);        

            # Adjust tick label size
            self.ax.tick_params(axis='both', which='major', labelsize=6);
            self.canvas.draw();

        def get_net_speed():
            while True:
                net_stat = psutil.net_io_counters()
                net_in_1 = net_stat.bytes_recv
                net_out_1 = net_stat.bytes_sent
                time.sleep(1)
                net_stat = psutil.net_io_counters()
                net_in_2 = net_stat.bytes_recv
                net_out_2 = net_stat.bytes_sent

                #Convert Bytes to Bits
                net_in = round((net_in_2 - net_in_1) * 8 / (1024 * 1024), 3)
                net_out = round((net_out_2 - net_out_1) * 8 / (1024 * 1024), 3)
                output = f"System Net-Usage:\nIN: {net_in} MB/s, OUT: {net_out} MB/s";

                # Print Stat
                self.Current_Bandwidth_Speed.configure(state='normal');
                self.Current_Bandwidth_Speed.delete("1.0", tk.END);
                self.Current_Bandwidth_Speed.insert("1.0", output);
                self.Current_Bandwidth_Speed.configure(state='disabled');
                

                self.net_in_values.append(net_in);
                self.net_out_values.append(net_out);
                # Keep Chart Under 60 Seconds
                if (len(self.net_in_values) > 60):
                    del self.net_in_values[0];
                    del self.net_out_values[0];
               
                if not self.stop_threads:
                    pass
        
                update_plot();
                
        threadSysBand = threading.Thread(target=get_net_speed);
        self.running_threads.append(threadSysBand);
        threadSysBand.daemon = True;
        threadSysBand.start();
    
    def get_adapters(self):
        self.interface_dict = devT.Get_Interface_Names();
        
        adapters = list(self.interface_dict.keys());   
        #Update Adapter List
        self.Select_Adapter['values'] = adapters;

    def bandwidth_usage_monitor_adapter(self, adapter_select):
        def get_net_speed():
            while True:
                try:
                    net_stat = psutil.net_io_counters(pernic=True)[self.adapter]
                    net_in_1 = net_stat.bytes_recv
                    net_out_1 = net_stat.bytes_sent
                    time.sleep(1)
                    net_stat = psutil.net_io_counters(pernic=True)[self.adapter]
                    net_in_2 = net_stat.bytes_recv
                    net_out_2 = net_stat.bytes_sent

                    net_in = round((net_in_2 - net_in_1) * 8 / (1024 * 1024), 3)
                    net_out = round((net_out_2 - net_out_1) * 8 / (1024 * 1024), 3)
                    output = f"Adapter Net-Usage:\nIN: {net_in} MB/s, OUT: {net_out} MB/s"

                    # Update GUI
                    self.Current_Adapter_Speed.configure(state='normal')
                    self.Current_Adapter_Speed.delete("1.0", tk.END)
                    self.Current_Adapter_Speed.insert("1.0", output)
                    self.Current_Adapter_Speed.configure(state='disabled')
                    
                    self.adapter_isLive = True;
                    
                    if not self.stop_threads:
                        pass
                except KeyError:
                    # Handle adapter not found in the dictionary
                    self.Current_Adapter_Speed.configure(state='normal')
                    self.Current_Adapter_Speed.delete("1.0", tk.END)
                    self.Current_Adapter_Speed.insert("1.0", "Adapter not found")
                    self.Current_Adapter_Speed.configure(state='disabled')

        # Select Adapter
        self.adapter = adapter_select;        

        # Start the new thread
        if not self.adapter_isLive:
            self.threadAdptBand = threading.Thread(target=get_net_speed)
            self.running_threads.append(self.threadAdptBand)
            self.threadAdptBand.daemon = True;
            self.threadAdptBand.start()        

        # Update Data
        if adapter_select in self.interface_dict:
            adapter_data = self.interface_dict[adapter_select]
            index = adapter_data.get('index', '')
            connection_type = adapter_data.get('connection_type', '')
            ipv4_addresses = ', '.join(adapter_data.get('ipv4_addresses', []))
            ipv6_addresses = ', '.join(adapter_data.get('ipv6_addresses', []))
            output = f"Name: {adapter_select}\nIndex: {index}\nConnection Type: {connection_type}\nIPv4 Addresses: {ipv4_addresses}\nIPv6 Addresses: {ipv6_addresses}\n"
        else:
            output = "Adapter not found in the interface dictionary."

        self.Current_Adapter_Details.configure(state='normal')
        self.Current_Adapter_Details.delete("1.0", tk.END)
        self.Current_Adapter_Details.insert("1.0", output)
        self.Current_Adapter_Details.configure(state='disabled')
        
    def get_networks(self):
        self.network_dict = scanT.Get_Network_Data();
    
        networks = list(self.network_dict.keys());
        self.Select_Network['values'] = networks;

    def select_network(self,network):
        self.current_network_dict = {}
        
        # Input Network Data
        self.current_network_dict["name"] = network;
        self.current_network_dict["hostname"] = self.network_dict[network]["hostname"];
        self.current_network_dict["ipv4"] = self.network_dict[network]["ipv4_address"];
        self.current_network_dict["subdomain"] = self.network_dict[network]["sub_domain"];
        self.current_network_dict["netmask"] = self.network_dict[network]["netmask"];
        self.current_network_dict["broadcast_ip"] = self.network_dict[network]["broadcast_ip"];

        # Update Output
        output = f"Name : {self.current_network_dict['name']}\n" \
        f"Hostname : {self.current_network_dict['hostname']}\n" \
        f"IPv4 : {self.current_network_dict['ipv4']}\n" \
        f"Subdomain : {self.current_network_dict['subdomain']}\n" \
        f"Netmask : {self.current_network_dict['netmask']}\n" \
        f"Broadcast IP : {self.current_network_dict['broadcast_ip']}"

        self.Current_Network_Details.configure(state='normal');
        self.Current_Network_Details.delete("1.0", tk.END)
        self.Current_Network_Details.insert('1.0', output);
        self.Current_Network_Details.configure(state='disabled');

        self.IP_Scanner_Input.configure(state='normal');
        self.IP_Scanner_Input.delete("1.0", tk.END)
        self.IP_Scanner_Input.insert('1.0', self.current_network_dict['subdomain']);
    
        # Get Start_IP, End_IP for Ping Sweeper
        start_ip, end_ip = scanT.Get_Start_End_IP_Ping(self.current_network_dict["netmask"],self.current_network_dict["subdomain"])

        self.Ping_Start_Input.delete("1.0", tk.END)
        self.Ping_End_Input.delete("1.0", tk.END)
        self.Ping_Start_Input.insert('1.0', start_ip);
        self.Ping_End_Input.insert('1.0', end_ip);

    def start_ip_scan(self,subdomain):
        Fail = False;
        if subdomain == "Input IP Address...":
            mb.showwarning("Alert", "No IP Given!")
            Fail = True;
  
        # Start the new thread
        if not self.ipscan_isLive and not Fail:
            self.threadIPScan = threading.Thread(target=self.find_ip_scan, args=(subdomain,))
            self.running_threads.append(self.threadIPScan)
            self.threadIPScan.daemon = True;
            self.threadIPScan.start()
            
        if not Fail:
            if self.ipscan_isLive:
                self.ipscan_isLive = False;
                self.Start_Stop_IP_Button.configure(text="START SCAN")
            else:
                self.ipscan_isLive = True;
                self.Start_Stop_IP_Button.configure(text="STOP SCAN")

    def find_ip_scan(self,subdomain):
        scapy.sniff(prn=lambda packet: self.find_ips(packet, subdomain), stop_filter=self.stop_find_ips)
        
    def find_ips(self,packet,subdomain):
        # Output to Console
        stdout = sys.stdout
        sys.stdout = StringIO()
        packet.show()
        packet_output = sys.stdout.getvalue()
        sys.stdout = stdout
        self.IP_Console_Output.configure(state='normal');
        self.IP_Console_Output.insert('1.0',"\nSearching for Packets...\n");
        self.IP_Console_Output.insert('1.0',packet_output);
        self.IP_Console_Output.configure(state='disabled');

        #Check ipv4 or ipv6
        if 'IP' in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            
            # Check Subdomain
            if src_ip[0:len(subdomain)] == subdomain:
                src_hostname = self.get_hostname(src_ip);
                dst_hostname = self.get_hostname(dst_ip);
                src = src_ip + " (" + src_hostname + ")";
                dest = src_ip + " (" + dst_hostname + ")";
                if src not in self.src_ip_dict:              
                    self.src_ip_dict[src] = [dest]
                    
                    # Append to Treeview
                    row = self.treev.insert('', index=tk.END, text=src)
                    self.treev.insert(row, tk.END, text=dest)
                    
                else:
                    if dest not in self.src_ip_dict[src]:
                        self.src_ip_dict[src].append(dest)
                        cur_item = self.treev.focus()
                    
                        if (self.treev.item(cur_item)['text'] == src):
                            self.treev.insert(cur_item, tk.END, text=dest)
                            
    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Hostname N/A" 
        
    def stop_find_ips(self,packet):
        return not self.ipscan_isLive
    
    def clear_ipscan(self):
        self.treev.delete(*self.treev.get_children());
        self.src_ip_dict = {};
        self.IP_Console_Output.configure(state='normal');
        self.IP_Console_Output.delete('1.0', tk.END);
        self.IP_Console_Output.configure(state='disabled');

    def start_ping_sweep(self,start_ip,end_ip):
        Fail = False;
        if start_ip == "Input Start Host..." or end_ip == "Input End Host...":
            mb.showwarning("Alert", "No Start or End Host Given!")
            Fail = True;
  
        # Start the new thread
        if not self.pingsweep_isLive and not Fail:
            self.threadPingSweep = threading.Thread(target=self.ping_sweep, args=(start_ip,end_ip, ))
            self.running_threads.append(self.threadPingSweep)
            self.threadPingSweep.daemon = True;
            self.threadPingSweep.start()
          
        if not Fail:
            if self.pingsweep_isLive:
                self.pingsweep_isLive = False;
                self.Start_Stop_Ping_Button.configure(text="START PING SWEEP")
            else:
                self.pingsweep_isLive = True;
                self.Start_Stop_Ping_Button.configure(text="STOP PING SWEEP")
                self.Ping_Hosts_Found.configure(state="normal");
                self.Ping_Console_Output.configure(state="normal");
                self.Ping_Hosts_Found.delete("1.0", tk.END)
                self.Ping_Console_Output.delete("1.0", tk.END)
                self.Ping_Hosts_Found.configure(state="disabled");
                self.Ping_Console_Output.configure(state="disabled");
            
    def ping_sweep(self,start_ip,end_ip):    
        # Perform the ping sweep    
        current_array = start_ip.split('.');
        current_ip = '.'.join(current_array)
        while self.pingsweep_isLive:
            self.Ping_Hosts_Found.configure(state="normal");
            self.Ping_Console_Output.configure(state="normal");
            
            if current_ip != end_ip:
                current_ip = '.'.join(current_array)
                start_index = len(current_array)-1;
                # Ping Current
                self.Ping_Console_Output.insert("1.0", "Pinging : " + current_ip);
                response = subprocess.run(['ping', current_ip], stdout=subprocess.PIPE)
                if response.returncode == 0:
                    self.Ping_Hosts_Found.insert("1.0", current_ip + "\n");
                    self.Ping_Console_Output.insert("1.0", "(Response Found!) ");
                # Update
                if current_array[start_index] == '255':
                    # Iterate
                    indices = [index for index, elem in enumerate(current_array) if elem == '255']
                    print(indices)
                    for index in indices:
                        current_array[index] = '0';
                        current_array[index-1] = str(int(current_array[index-1]) + 1)
                else:
                    current_array[start_index] = str(int(current_array[start_index]) + 1)
                self.Ping_Console_Output.insert("1.0", "\n");  
            self.Ping_Hosts_Found.configure(state="disabled");
            self.Ping_Console_Output.configure(state="disabled");
 
    def scan_button_select(self,selection,local,subdomain):
        if selection == 1:
            ip = local;
        elif selection == 2:
            ip = "";
        elif selection == 3:
            if subdomain == "No Subdomain Available":
                ip = "No Subdomain Available";
            else:
                array = subdomain.split('.')
                while len(array) < 4:
                    array.append('0');
                array[len(array)-1] = 1;
                strarray = [str(i) for i in array]
                octets = '.'.join(strarray);
                ip = octets + '-255';  
       
        self.NMAP_Scanner_Input.delete("1.0", tk.END);
        self.NMAP_Scanner_Input.insert("1.0", ip);
       
    def start_nmap_scan(self,ip,scan,start,end):
        Fail = False;
        scan_dict={'SYN Scan':['-sS']}
        if scan not in scan_dict.keys() and isinstance(start, int) and isinstance(end, int):
            mb.showwarning("Alert", "Invalid Inputs!")
            Fail = True;
  
        # Start the new thread
        if not self.NMAPScan_isLive and not Fail:
            self.threadNMAPScan = threading.Thread(target=self.nmap_scan, args=(ip,scan,start,end ))
            self.running_threads.append(self.threadNMAPScan)
            self.threadNMAPScan.daemon = True;
            self.threadNMAPScan.start()
          
        if not Fail:
            if self.NMAPScan_isLive:
                self.NMAPScan_isLive = False;
                self.Start_Stop_NMAP_Button.configure(text="START NMAP SCAN")
            else:
                self.NMAPScan_isLive = True;
                self.Start_Stop_NMAP_Button.configure(text="STOP NMAP SCAN")
                #self.NMAP_Console_Output.configure(state="normal");
                #self.Ping_Console_Output.configure(state="normal");
                #self.Ping_Hosts_Found.delete("1.0", tk.END)
                #self.Ping_Console_Output.delete("1.0", tk.END)
                #self.Ping_Hosts_Found.configure(state="disabled");
                #self.Ping_Console_Output.configure(state="disabled");
    
    def nmap_scan(self,ip,scan,start,end): 
        self.NMAP_Console_Output.configure(state="normal");
        self.NMAP_Output.configure(state="normal");
        self.NMAP_Console_Output.delete('1.0', tk.END);
        self.NMAP_Output.delete('1.0', tk.END);
        self.NMAP_Console_Output.insert('1.0', "Starting NMAP Scan...\n");
        scanner = nmap.PortScanner()
        scan_dict={'SYN Scan':['-sS']}
        ports = start + "-" + end;
        self.NMAP_Console_Output.insert('1.0', "NMAP version: " + ".".join(map(str, scanner.nmap_version())) + "\n");
        self.NMAP_Console_Output.insert('1.0', "Scanning IP: " + ip + "\n");
        scanner.scan(ip,ports,scan_dict[scan][0]) #the # are port range to scan, the last part is the scan type
        scan_info = scanner.scaninfo();
        output = "NMAP Version: " + ".".join(map(str, scanner.nmap_version()));
        output += "\nIP Address" + ip;
        output += "\nPorts: " + start + " - " + end;
        for host in scanner.all_hosts():
                output += "\nHost: " + host;
                for proto in scanner[host].all_protocols():
                    output += "\nProtocol:" + str(proto.upper())
                    open_ports = scanner[host][proto].keys()
                    output += "\nOpen Ports: " + ", ".join(map(str, open_ports)) 
                    
        self.NMAP_Console_Output.insert('1.0', "Scan Complete\n");
        self.NMAP_Output.insert('1.0', output);
        self.NMAP_Console_Output.configure(state="disabled");
        self.NMAP_Output.configure(state="disabled");

        # Reset
        self.NMAPScan_isLive = False;
        self.Start_Stop_NMAP_Button.configure(text="START NMAP SCAN")

#Instantiate & Initialize
GUI = GUI(window); 
window.mainloop(); 
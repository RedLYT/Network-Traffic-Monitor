from csv import Sniffer
from re import I
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
    interface_dict = "";    
    adapter = "";
    adapter_isLive = False;

    def __init__(self, master=None): 
        #Stop Thread Event
        self.stop_event = threading.Event()        
        
        #Tabs
        tabTools = ttk.Notebook(window);
        device = ttk.Frame(tabTools);
        scanners = ttk.Frame(tabTools);
        nmap = ttk.Frame(tabTools);
        sniffer = ttk.Frame(tabTools);
        lldpa = ttk.Frame(tabTools);

        tabTools.add(device, text="Device");
        tabTools.add(scanners, text="Network Scanners");
        tabTools.add(nmap, text="NMAP Scanner");
        tabTools.add(sniffer, text="Packet Sniffer");
        tabTools.add(lldpa, text="LLDP Packet Analyzer");
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
        devD_Width = 295;
        self.Current_Bandwidth = tk.LabelFrame(device);
        self.Current_Bandwidth.configure(height=devC_Height, width=devC_Width, borderwidth=3, relief="groove", text="Bandwidth Info");
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
        threadStat = threading.Thread(target=run_netstat, name="threadStat");
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
               
        
                update_plot();
                
        threadSysBand = threading.Thread(target=get_net_speed, name="threadSysBand");
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
            self.threadAdptBand = threading.Thread(target=get_net_speed, name="threadAdptBand")
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

#Instantiate & Initialize
GUI = GUI(window); 
window.mainloop(); 
import customtkinter as ctk
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, RadioTap
import threading
import time
import json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# GUI background
app = ctk.CTk()
app.title("Drone Deauth Detection Module")
app.geometry("700x400")

# Showing Status
label = ctk.CTkLabel(app, text="Status: Detecting (Safe)", text_color="green", font=("Arial", 20))
label.pack(pady=50)

mac_history = {}
attack_counter = {}
protected_drone_macs = []



# # Read the drones information in the json file
# def load_drone_json(filepath='drones.json'):
#     try:
#         with open(filepath,'r') as file:
#             return json.load(file)
#     # Check if the json config file is here. 
#     # It records the Drone's profile data.
#     # The details of the json content are in the readme file under "Drone-Deauth-Detect-And-Response-System" folder.  
#     except FileNotFoundError:
#         label.configure(text=f'No json config file found.')
#         return{}

# drones_data=load_drone_json()
# for drone_name, details in drones_data.items():
#     if isinstance(details,dict):
#         if "mac_address" in details:
#             protected_drone_macs.append(details["mac_address"].upper())
#         if "ap_mac" in details:
#             protected_drone_macs.append(details["ap_mac"].upper())


# Detailed Warning Display
def trigger_warning(src_mac, dest_mac, reason):
    global label
    warning_text = (
        f"Warning: Deauth Detected! \n"
        f"Attacker (Source) mac: {src_mac} \n"
        f"Target (Destination): {dest_mac}\n"
        f"Reason: {reason}"
    )    
    label.configure(text=warning_text, text_color="red")

def detect_deauth(packet):
    # Detect Wifi packet
    if packet.haslayer(Dot11):
        # Check if it is management frame
        # And check if it is deauth or disassociation
        if pkt_type == 0 and (pkt_subtype == 12 or pkt_subtype == 10):
            if packet.addr3 == "60:60:1F:60:9F:CD":

                dest_mac = packet.addr1
                src_mac = packet.addr2
                pkt_type = packet.type
                pkt_subtype = packet.subtype

                if src_mac is None:
                    return

                # Extract Sequence Number
                try:
                    current_seq = packet[Dot11].SC >> 4
                except AttributeError:
                    current_seq = 0

                retry_bit=(packet.FCfield & 0x08)!=0
                previous_seq=mac_history.get(src_mac,{}).get("seq",-1)
                # Detection Logic:
                # Pretend Resend Attack: is retry but sequence nubmer is different
                if previous_seq!= -1 and retry_bit and (current_seq!=previous_seq):
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Pretend Resend Attack")
                    mac_history[src_mac]={"seq":current_seq,"time":time.time()}
                    return

                # Replay Attack: is not retry but sequence nubmer is the same
                if previous_seq!=-1 and not retry_bit and (current_seq==previous_seq):
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Replay Attack")
                    mac_history[src_mac]={"seq":current_seq,"time":time.time()}
                    return  

                # Deauth Flood Attack
                current_time = time.time()

                    
        return
    return

def keep_sniffing():
    print("Monitoring WiFi Packets...")
    sniff(iface="wlan0", prn=detect_deauth, store=0)

sniff_thread = threading.Thread(target=keep_sniffing, daemon=True)
sniff_thread.start()

app.mainloop()
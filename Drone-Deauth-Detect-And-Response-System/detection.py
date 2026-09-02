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

        pkt_type = packet.type
        pkt_subtype = packet.subtype
        # Check if it is management frame
        # And check if it is deauth or disassociation
        if pkt_type == 0 and (pkt_subtype == 12 or pkt_subtype == 10):
            if packet.addr3 and packet.addr3.upper() == "60:60:1F:60:9F:CD":

                dest_mac = packet.addr1
                src_mac = packet.addr2


                if src_mac is None:
                    return

                print(f"Deauth Packets Detected:{src_mac}")

                # Extract Sequence Number
                try:
                    current_seq = packet[Dot11].SC >> 4
                except AttributeError:
                    current_seq = 0

                retry_bit=(packet.FCfield & 0x08)!=0
                previous_seq=mac_history.get(src_mac,{}).get("seq",-1)
                # Detection Logic:
                # (1) Pretend Resend Attack: is retry but sequence nubmer is different
                if previous_seq!= -1 and retry_bit and (current_seq!=previous_seq):
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Pretend Resend Attack")
                    mac_history[src_mac]={"seq":current_seq,"time":time.time()}
                    return

                # (2) Replay Attack: is not retry but sequence nubmer is the same
                if previous_seq!=-1 and not retry_bit and (current_seq==previous_seq):
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Replay Attack")
                    mac_history[src_mac]={"seq":current_seq,"time":time.time()}
                    return  

                # (3) Deauth Flood Attack
                current_time = time.time()

                if src_mac not in attack_counter:
                    attack_counter[src_mac]=[]

                attack_counter[src_mac].append(current_time)

                attack_counter[src_mac]=[t for t in attack_counter[src_mac]if current_time-t<=2]

                packets_within_2s=len(attack_counter[src_mac])
                packets_within_0_1s=len([t for t in attack_counter[src_mac]if current_time-t<=0.1])

                if packets_within_0_1s>=5:
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Flood Attack-5 packets within 0.1s")
                    attack_counter[src_mac]=[]

                if packets_within_2s>=20:
                    app.after(0,trigger_warning,src_mac,dest_mac,"Deauth: Flood Attack-20 packets within 2s")
                    attack_counter[src_mac]=[]

                mac_history
        return
    return

def keep_sniffing():
    print("Monitoring WiFi Packets...")
    sniff(iface="wlan0", prn=detect_deauth, store=0)

sniff_thread = threading.Thread(target=keep_sniffing, daemon=True)
sniff_thread.start()

app.mainloop()
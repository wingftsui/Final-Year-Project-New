import customtkinter as ctk
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, RadioTap
import threading
import time

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
        dest_mac = packet.addr1
        src_mac = packet.addr2
        pkt_type = packet.type
        pkt_subtype = packet.subtype

        if src_mac is None:
            return

        current_time = time.time() 
        
        try:
            current_seq = packet[Dot11].SC >> 4
        except AttributeError:
            current_seq = 0

        current_rssi = None

        # Extract RSSI
        if packet.haslayer(RadioTap):
            try:
                current_rssi = packet[RadioTap].dBm_AntSignal
            except AttributeError:
                pass

        # Detection Logic:
        # Check if it is management frame
        # And check if it is deauth or disassociation
        if pkt_type == 0 and (pkt_subtype == 12 or pkt_subtype == 10):
            if src_mac in mac_history:
                previous_time = mac_history[src_mac]["time"]
                previous_seq = mac_history[src_mac].get("seq", current_seq)
                previous_rssi = mac_history[src_mac].get("rssi", None)
                
                time_diff = current_time - previous_time

            
                if time_diff <= 2:
                    rssi_info="N/A"
                    if current_rssi is not None and previous_rssi is not None:
                        rssi_delta = abs(current_rssi-previous_rssi)
                        rssi_info = f"{rssi_delta} dBm"

                    is_abnormal = False
                    reason_msg = "Deauth Flood Attack"

                    # 1st Round Checking: Check any abnormal situation in sequence number in management frame
                    seq_diff = abs(current_seq - previous_seq)
                    if 50 < seq_diff < 4046:
                        is_abnormal = True
                        reason_msg = f"RSSI Delta: {rssi_delta} dBm"                

                    if attack_counter.get(src_mac,0) > 0:
                        attack_counter[src_mac] += 1
                    elif is_abnormal:
                        attack_counter[src_mac] = 1
                    else:
                        attack_counter[src_mac] = 0
                    
                    if attack_counter.get(src_mac,0)>=5:
                        print("Warning: Deauth Attack Detected!")
                        app.after(0, trigger_warning, src_mac, dest_mac, reason_msg)
                        attack_counter[src_mac] = 0
                        return
                    
        mac_history[src_mac] = {
            "time": current_time,
            "seq": current_seq,
            "rssi": current_rssi 
        }

def keep_sniffing():
    print("Monitoring WiFi Packets...")
    sniff(iface="wlan0", prn=detect_deauth, store=0)

sniff_thread = threading.Thread(target=keep_sniffing, daemon=True)
sniff_thread.start()

app.mainloop()
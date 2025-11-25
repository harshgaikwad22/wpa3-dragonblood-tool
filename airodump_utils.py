import os
import subprocess
import time
import glob
import sys

def ap_discovery_airodump(interface, folder_name):
  # Run airodump-ng to capture packets for 1 minute. -- Using popen to kill airodump after 1min.
  try:
    print(f"Finding vulnerable AP(s) using {interface}...")
    # Ensure the folder exists
    os.makedirs(folder_name, exist_ok=True)
    
    airodump_cmd = [
      'airodump-ng', interface,
      '-w', os.path.join(folder_name, 'discovery'),
      '--output-format', 'pcap',
      '--manufacturer', '--wps', '--band', 'abg'
    ]
    with open(os.devnull, 'w') as FNULL:
      airodump_process = subprocess.Popen(airodump_cmd, stdout=FNULL, stderr=FNULL)
      time.sleep(60)
      airodump_process.terminate()
      airodump_process.wait()  # Ensure process is cleaned up
    
    # List created files for debugging
    pcap_files = glob.glob(os.path.join(folder_name, "discovery-*.pcap"))
    cap_files = glob.glob(os.path.join(folder_name, "discovery-*.cap"))
    all_files = pcap_files + cap_files
    print(f"Created capture files: {all_files}")
    
    print(f"Capture done. Files are saved under '{folder_name}/'.")
  except Exception as e:
    print(f"Error during airodump-ng execution : {e}")
    sys.exit(1)
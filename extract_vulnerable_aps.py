from collections import defaultdict
from extract_security_info import extract_security_info
from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11, RadioTap

def extract_channel(packet):
  # Extract the channel from a packet if available.
  channel = None
  
  # Try to get channel from RadioTap pseudo-header first (most reliable)
  if packet.haslayer(RadioTap):
    radiotap = packet[RadioTap]
    if hasattr(radiotap, 'ChannelFrequency'):
      # Convert frequency to channel
      freq = radiotap.ChannelFrequency
      if 2412 <= freq <= 2484:  # 2.4 GHz
        channel = (freq - 2412) // 5 + 1
      elif 5170 <= freq <= 5825:  # 5 GHz
        channel = (freq - 5170) // 5 + 34
    elif hasattr(radiotap, 'channel'):
      channel = radiotap.channel
  
  # If still no channel, try Direct Sequence Parameter Set in beacon elements
  if channel is None and packet.haslayer(Dot11Elt):
    try:
      elt = packet[Dot11Elt]
      while elt:
        if elt.ID == 3:  # Direct Sequence Parameter Set (Frequency and channel related information)
          if len(elt.info) >= 1:
            channel = ord(elt.info[0:1])
            break
        elt = elt.payload.getlayer(Dot11Elt)
    except:
      pass
  
  # Last resort: try Dot11Beacon channel attribute
  if channel is None and packet.haslayer(Dot11Beacon):
    beacon = packet[Dot11Beacon]
    try:
      channel = beacon.channel
    except AttributeError:
      pass
  
  return channel

def extract_vulnerable_aps(file):
  # Analyzes a PCAP file to detect APs vulnerable to Dragonblood.
  try:
    packets = rdpcap(file)
  except Exception as e:
    print(f" Error reading PCAP file {file}: {e}")
    return []
      
  ssid_info = defaultdict(list)
  
  print(f" Analyzing {len(packets)} packets from {file}")

  beacon_count = 0
  for packet in packets:
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
      beacon_count += 1
      try:
        ssid, version, cipher, auth, mfp = extract_security_info(packet)
        channel = extract_channel(packet)
        
        # Skip empty or hidden SSIDs
        if not ssid.strip() or ssid == "Unknown":
          continue
            
        bssid = packet[Dot11].addr3
        
        # Check if we already have this BSSID with the same SSID
        found = False
        for existing in ssid_info[ssid]:
          if existing["BSSID"] == bssid:
            found = True
            break
        
        if not found:
          ssid_info[ssid].append({
            "Version": version,
            "Cipher": cipher,
            "Auth": auth,
            "MFP": mfp,
            "BSSID": bssid,
            "Channel": channel
          })
      except Exception as e:
        continue  # Skip packets that cause errors
  
  # Print all detected SSIDs with their AKM suites for debugging
  print(f"\nAll detected SSIDs and their authentication methods:")
  print("-" * 80)
  for ssid, details in ssid_info.items():
    for detail in details:
      print(f"SSID: {ssid[:30]:30} | BSSID: {detail['BSSID']} | Auth: {detail['Auth']:20} | Version: {detail['Version']:6} | MFP: {detail['MFP']:10}")
  print("-" * 80)
  
  vulnerable_aps = []
  wpa3_only_aps = []
  transition_aps = []
  
  # Filter and display both WPA3-only and transition mode APs
  unique_bssids = set()
  for ssid, details in ssid_info.items():
    for detail in details:
      if detail["BSSID"] not in unique_bssids:
        unique_bssids.add(detail["BSSID"])
        
        auth_methods = detail["Auth"].split(", ")
        has_sae = any("SAE" in auth for auth in auth_methods)
        has_psk = any("PSK" in auth for auth in auth_methods)
        
        if has_sae:
          ap_info = {
            "SSID": ssid,
            "BSSID": detail["BSSID"],
            "Channel": detail["Channel"],
            "Version": detail["Version"],
            "Cipher": detail["Cipher"],
            "Auth": detail["Auth"],
            "MFP": detail["MFP"],
            "Type": "WPA3-Only" if not has_psk else "WPA3/2-Transition"
          }
          
          if has_sae and not has_psk:
            wpa3_only_aps.append(ap_info)
            print(f"Found WPA3-only AP: {ssid}")
          elif has_sae and has_psk:
            transition_aps.append(ap_info)
            print(f"Found WPA3/2 Transition mode AP: {ssid}")

  # Combine both types of vulnerable APs
  vulnerable_aps = wpa3_only_aps + transition_aps
  
  if not vulnerable_aps:
    print("No vulnerable APs were found in the file.")
    print("Looking for APs that support WPA3 (SAE) authentication.")
    return vulnerable_aps
  
  # Display vulnerable APs by type
  if wpa3_only_aps:
    print(f"\n Found {len(wpa3_only_aps)} WPA3-only AP(s):")
    for i, ap in enumerate(wpa3_only_aps, 1):
      print(f"\n[{i}] [WPA3-Only AP] :")
      print(f"  - SSID: {ap['SSID']}")
      print(f"  - BSSID: {ap['BSSID']}")
      print(f"  - Channel: {ap['Channel']}")
      print(f"  - Security Protocol: {ap['Version']}")
      print(f"  - Cipher: {ap['Cipher']}")
      print(f"  - Authentication: {ap['Auth']}")
      print(f"  - MFP: {ap['MFP']}\n")
  
  if transition_aps:
    print(f"\n Found {len(transition_aps)} WPA3/2 Transition mode AP(s):")
    for i, ap in enumerate(transition_aps, 1):
      print(f"\n[{i}] [WPA3/2 Transition AP - VULNERABLE TO DRAGONBLOOD] :")
      print(f"  - SSID: {ap['SSID']}")
      print(f"  - BSSID: {ap['BSSID']}")
      print(f"  - Channel: {ap['Channel']}")
      print(f"  - Security Protocol: {ap['Version']}")
      print(f"  - Cipher: {ap['Cipher']}")
      print(f"  - Authentication: {ap['Auth']}")
      print(f"  - MFP: {ap['MFP']}\n")
  
  return vulnerable_aps

def ap_selection(vulnerable_aps):
  """Allow user to select which APs to attack with network type information"""
  if not vulnerable_aps:
    return []
  
  # Separate WPA3-only and transition mode APs
  wpa3_only_aps = [ap for ap in vulnerable_aps if ap.get('Type') == 'WPA3-Only']
  transition_aps = [ap for ap in vulnerable_aps if ap.get('Type') == 'WPA3/2-Transition']
  
  print(f"\nFound {len(vulnerable_aps)} target AP(s). Please select which ones to attack:")
  print("-" * 100)
  
  all_aps = []
  index = 1
  
  # Display WPA3-only APs first
  if wpa3_only_aps:
    print(f"[WPA3-Only APs]")
    for ap in wpa3_only_aps:
      print(f"[{index}] WPA3-Only | SSID: {ap['SSID']:30} | BSSID: {ap['BSSID']} | Channel: {ap['Channel']}")
      all_aps.append(ap)
      index += 1
  
  # Display transition mode APs
  if transition_aps:
    print(f"[WPA3/2 Transition APs - VULNERABLE TO DRAGONBLOOD]")
    for ap in transition_aps:
      print(f"[{index}] Transition | SSID: {ap['SSID']:30} | BSSID: {ap['BSSID']} | Channel: {ap['Channel']}")
      all_aps.append(ap)
      index += 1
  
  print("-" * 100)
  
  while True:
    try:
      choice = input("\n[?] Enter your selection (e.g., 1,3,5): ").strip().upper()
      selected_indices = []
      for part in choice.split(','):
        part = part.strip()
        if part.isdigit():
          index = int(part)
          if 1 <= index <= len(all_aps):
            selected_indices.append(index)
          else:
            print(f" Invalid selection: {index}. Must be between 1 and {len(all_aps)}")
        elif part:
          print(f" Invalid selection: {part}")
      
      if selected_indices:
        selected_aps = [all_aps[i-1] for i in selected_indices]
        print(f" Selected {len(selected_aps)} AP(s) for attack:")
        for i, ap in enumerate(selected_aps, 1):
          ap_type = ap.get('Type', 'Unknown')
          print(f"    {i}. {ap_type} - {ap['SSID']} ({ap['BSSID']})")
        return selected_aps
      else:
        print("No valid APs selected. Please try again.")
    except KeyboardInterrupt:
      print("\nSelection cancelled by user.")
      return []
    except Exception as e:
      print(f"Error in selection: {e}. Please try again.")
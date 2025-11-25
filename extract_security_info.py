from scapy.all import Dot11Elt, Dot11Beacon

def parse_rsn_info(rsn_info):
  # Parsing RSN information to determine WPA version, ciphers, authentication and MFP.
  version = "Unknown"
  ciphers = []
  auths = []
  mfp = "Inactive"
  
  if len(rsn_info) < 2:
    return version, ", ".join(ciphers), ", ".join(auths), mfp
  
  try:
    rsn_version = int.from_bytes(rsn_info[0:2], byteorder='little')
    if rsn_version == 1:
      version = "WPA2"
    elif rsn_version == 2:
      version = "WPA3"
    
    if len(rsn_info) >= 8:
      cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder='little')
      cipher_offset = 8 + cipher_suite_count * 4
      
      for i in range(cipher_suite_count):
        if 12 + i*4 <= len(rsn_info):
          cipher_suite = rsn_info[8 + i*4:12 + i*4]
          if len(cipher_suite) >= 4:
            if cipher_suite[3] == 2:
              ciphers.append("TKIP")
            elif cipher_suite[3] == 4:
              ciphers.append("CCMP")
            elif cipher_suite[3] == 8:
              ciphers.append("GCMP")
      
      if len(rsn_info) >= cipher_offset + 2:
        akm_suite_count = int.from_bytes(rsn_info[cipher_offset:cipher_offset+2], byteorder='little')
        akm_offset = cipher_offset + 2
          
        for i in range(akm_suite_count):
          if akm_offset + (i+1)*4 <= len(rsn_info):
            akm_suite = rsn_info[akm_offset + i*4:akm_offset + (i+1)*4]
            if len(akm_suite) >= 4:
              if akm_suite[3] == 1:
                auths.append("802.1X (Enterprise)")
              elif akm_suite[3] == 2:
                auths.append("PSK")
              elif akm_suite[3] == 8:
                auths.append("SAE")
                version = "WPA3"
              elif akm_suite[3] == 3:
                auths.append("FT-802.1X")
              elif akm_suite[3] == 4:
                auths.append("FT-PSK")
              elif akm_suite[3] == 9:
                auths.append("802.1X-SHA256")
              elif akm_suite[3] == 10:
                auths.append("PSK-SHA256")
              elif akm_suite[3] == 11:
                auths.append("SAE-EXT-KEY")
              elif akm_suite[3] == 12:
                auths.append("AP-PEER-KEY")
              else:
                auths.append(f"Unknown({akm_suite[3]})")
          
        if len(rsn_info) >= akm_offset + akm_suite_count * 4 + 2:
          rsn_capabilities = int.from_bytes(rsn_info[akm_offset + akm_suite_count * 4:akm_offset + akm_suite_count * 4 + 2], byteorder='little')
          if rsn_capabilities & 0b01000000:
            mfp = "Optional"
          if rsn_capabilities & 0b10000000:
            mfp = "Required"
  except Exception as e:
    print(f"[-] Error parsing RSN info: {e}")
  
  return version, ", ".join(ciphers), ", ".join(auths), mfp

## Only beacons and probe responses are passed here.
def extract_security_info(packet):
  # Retrieves 802.11 packet's information.
  ssid = "Unknown"
  try:
    ssid = packet[Dot11Elt].info.decode(errors="ignore")
  except:
    ssid = "Unknown"
  
  rsn_info = None
  wpa_info = None
  
  try:
    elt = packet[Dot11Elt]
    while elt:
      if elt.ID == 48:  # RSN Information (WPA2/WPA3)
        rsn_info = elt.info
      elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA Information (WPA)
        wpa_info = elt.info
      elt = elt.payload.getlayer(Dot11Elt)
  except:
    pass
  
  if rsn_info:
    version, cipher, auth, mfp = parse_rsn_info(rsn_info)
  elif wpa_info:
    version, cipher, auth, mfp = "WPA", "TKIP", "PSK", "Inactive"
  else:
    # Check if it's an open network
    if packet.haslayer(Dot11Beacon):
      cap = packet[Dot11Beacon].cap
      if cap & 0x10:  # Privacy bit set
        version, cipher, auth, mfp = "WEP", "WEP", "Open", "Inactive"
      else:
        version, cipher, auth, mfp = "Open", "None", "Open", "Inactive"
    else:
      version, cipher, auth, mfp = "Unknown", "Unknown", "Unknown", "Inactive"
  
  return ssid, version, cipher, auth, mfp

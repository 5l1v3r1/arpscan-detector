from scapy.all import *
import threading
from netaddr import *
import os
import sys
#==============================
gateway = input(">> [?] Enter Gateway Address: ")
cidr = (str(gateway) + "/24")
#===============================
clients = []
active_clients = []
nonactive_clients = []
#===============================
for ip in IPNetwork(cidr):
	clients.append(ip)

print(">> [+] All Possible Hosts Generated")

print(">> [*] Scanning Entire Network CIDR For Possible Active Clients. It Will Take Exactly 1 Minute, So Relax!")
#===============================
def scan_hosts():
	try:
		conf.verb = 0
		pkt = ARP(pdst=str(i))
		resp = sr1(pkt,timeout=0.2)
		if(resp == None):
			nonactive_clients.append(str(i))
			pass
		else:
			print(">> [+] " + str(i) + " is an active host")
			active_clients.append(str(i))
			pass
	except Exception as e:
		print("Error Occured!: " + str(e))

for i in clients:
	t = threading.Thread(target=scan_hosts)
	t.start()
	time.sleep(0.2)
#============================

print(">> [*] Passively Sniffing If One of the Active Clients Scans The Network For Active Hosts")
arp_pkts = []
def filter(pkt):
	if(pkt.haslayer("ARP")):
		if(pkt.psrc in active_clients and pkt.pdst in nonactive_clients):
			arp_pkts.append(pkt)
			if(len(arp_pkts) < 3):
				pass
			else:
				print (">> [+] Someone is ARP Scanning The Network For Potential Clients ! Beware of Getting Caught!")
				print (">> [+] Directly Killed the Network Manager So You Wont Get Detected By The Owner ;) You Are Welcome! See Ya!")
				arp_pkts.clear()
				os.system("service network-manager stop")
				sys.exit()

#=======================
while True:
	sniff(iface="wlan0", prn=filter)

